#include <ios>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <climits>

#include <string.h>
#include <elf.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <unistd.h>
#include <utility>

#include "loader.hpp"
#include "helper.hpp"

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

int Loader::read_bin()
{
    if ( 
        !std::filesystem::exists(this->bin_path) ||
        !std::filesystem::exists(this->lib_path))
    {
        throw std::runtime_error("Error: Can't find file");
    }

    std::ifstream f(this->bin_path);
    f.seekg(0, std::ios::end);
    this->bin_b.resize(f.tellg());
    f.seekg(0, std::ios::beg);
    
    f.read(reinterpret_cast<char*>(&this->bin_b[0]), this->bin_b.size());
    return 0;
}

int Loader::parse_headers()
{
    ElfW(Ehdr)* header = 
        reinterpret_cast<ElfW(Ehdr)*>(&this->bin_b[0]);    

    if (header->e_type == ET_DYN)
    {
        this->is_pie = true;
    }
    else
    {
        this->is_pie = false;
    }

    this->phnum = header->e_phnum;
    this->is_static = true;
    this->offset_phdr = header->e_phoff;
    
    // At this point entry is either an offset ( in case of PIE binary ) 
    // or an real v_addr, it will change after mmap
    this->entry = (void*)header->e_entry;

    for (int count = 0; count < this->phnum ; count++)
    {
        char* interp_name;
        ElfW(Phdr)* phdr = 
            reinterpret_cast<ElfW(Phdr)*>(
                &this->bin_b[header->e_phoff + count * sizeof(ElfW(Phdr))]);    

        // Found an interpreter
        if ( phdr->p_type == PT_INTERP)
        {
            this->is_static = false;
            interp_name = reinterpret_cast<char*>(&this->bin_b[phdr->p_offset]);
            std::cout << "Interp is " << interp_name << std::endl;
            this->interp_path = std::filesystem::path(interp_name);
        }

        // Save the PT_LOAD segments for mmap/mprotect later
        else if ( phdr->p_type == PT_LOAD)
        {
             
            struct Memory m {
                .addr = (void*)phdr->p_vaddr, 
                .size = phdr->p_memsz,
                .file_size = phdr->p_filesz,
                .offset = phdr->p_offset,
                .prot = phdr->p_flags
            };
            this->pt_loads.push_back(m);
        }
    }

    // Assume that there's at least 1 PT_LOAD entry and that's the PT_LOAD
    // corresponding to the binary header
    if ( this->is_pie )
    {
        // this will be overriden when mapping the binary
        this->bin_base = 0;
    }
    else 
    {
        this->bin_base = this->pt_loads[0].addr;
    }
    return 0;
}

int Loader::map_bin()
{
    unsigned long max = 0;
    unsigned long page_size = getpagesize();

    // find the highest address to load and align it to PAGE_SIZE
    for (auto& m : this->pt_loads)
    {
        unsigned long rounded = 
            (1 + (((unsigned long) m.addr + m.size) / page_size))
            * page_size;

        if ((unsigned long)m.addr + rounded > max)
        {
            max = rounded;
        }
    }

    // map where our binary will reside
    long r = 
        (long)mmap ( 
            this->bin_base, 
            max, 
            PROT_READ | PROT_WRITE, 
            MAP_ANON | MAP_PRIVATE, 
            0, 
            0);

    if (r == -1)
    {
        throw std::runtime_error("Error: mmap failed"); 
    }
    // Set bin base ( it was 0 for PIE binaries )
    else 
    {
        this->bin_base = (void*)r;
    }

    // Fix entry as it was an offset for PIE binaries
    if (this->is_pie)
    {
        this->entry = (void*) (r + (unsigned long)this->entry);
    }

    std::cout << "Binary mapped at: " << 
    std::hex << this->bin_base << std::endl;

    for (auto& m : this->pt_loads)
    {
        // we need to write the vaddr for PIE binary as it's still 0, ...
        if ( this->is_pie )
        {
            m.addr = (void*)((long)this->bin_base + (long)m.addr);
        }

        // then we copy the content in memory
        memcpy(m.addr, &this->bin_b[m.offset], m.file_size);

        // and we restore memory rights
        int flags = 0;
        if ( m.prot == (PF_X | PF_R) )
        {
            flags = PROT_READ | PROT_EXEC;
        }
        else if ( m.prot == (PF_W | PF_R) )
        {
            flags = PROT_READ | PROT_WRITE;
        }
        else if ( m.prot ==  PF_R)
        {
            flags = PROT_READ ;
        }
        int r =
            mprotect((void*)((long)m.addr & ~(page_size - 1)), m.size, flags);
        if (r == -1)
        {
            throw std::runtime_error("Error: mprotect failed"); 
        }
    }
    return 0;
}

int Loader::load_lib()
{
    void * handle;
    void (*fun)(void*);
    if((handle = dlopen(this->lib_path.c_str(), RTLD_LAZY)) == NULL)
    {
            throw std::runtime_error("Error: dlopen failed"); 
    }

    if((fun = (void (*)(void*)) dlsym(handle, "init")) == NULL)
    {
        throw std::runtime_error(
            "Error: dlsym failed. Does library contain"
            " export 'init'?\n"); 
    }

    fun(this->bin_base);

    return 0;
}

int Loader::map_interp()
{

    std::vector<uint8_t> interp_b;
    std::vector<struct Memory> pt_loads;
    std::ifstream f(this->interp_path);

    f.seekg(0, std::ios::end);
    interp_b.resize(f.tellg());
    f.seekg(0, std::ios::beg);
    
    f.read(reinterpret_cast<char*>(&interp_b[0]), interp_b.size());
    ElfW(Ehdr)* header = 
        reinterpret_cast<ElfW(Ehdr)*>(&interp_b[0]);    

    int phnum = header->e_phnum;
    this->interp_entry = (void*)header->e_entry;

    for (int count = 0; count < phnum ; count++)
    {
        ElfW(Phdr)* phdr = 
            reinterpret_cast<ElfW(Phdr)*>(
                &interp_b[header->e_phoff + count * sizeof(ElfW(Phdr))]);    

        if ( phdr->p_type == PT_LOAD)
        {
             
            struct Memory m {
                .addr = (void*)phdr->p_vaddr, 
                .size = phdr->p_memsz,
                .file_size = phdr->p_filesz,
                .offset = phdr->p_offset,
                .prot = phdr->p_flags
            };
            pt_loads.push_back(m);
        }
    }

    unsigned long max = 0;
    unsigned long page_size = getpagesize();
    for (auto& m : pt_loads)
    {
        unsigned long rounded = 
            (1 + (((unsigned long) m.addr + m.size) / page_size))
            * page_size;

        if ((unsigned long)m.addr + rounded > max)
        {
            max = rounded;
        }
    }

    // interp is always PIE so addr is 0
    long r = 
        (long)mmap ( 
            0, 
            max, 
            PROT_READ | PROT_WRITE, 
            MAP_ANON | MAP_PRIVATE, 
            0, 
            0);

    if (r == -1)
    {
        throw std::runtime_error("Error: mmap failed"); 
    }
    else 
    {
        this->interp_base = (void*)r;
    }

    // fix entry as interp is PIE (entry was an offset)
    this->interp_entry = (void*) (r + (unsigned long)this->interp_entry);

    std::cout << "interp mapped at: " << 
    std::hex << this->interp_base << std::endl;

    for (auto& m : pt_loads)
    {
        // we need to write the vaddr for PIE binary as it's still 0, ...
        m.addr = (void*)((long)this->interp_base+ (long)m.addr);

        // then we copy the content in memory
        memcpy(m.addr, &interp_b[m.offset], m.file_size);

        // and we restore memory rights
        int flags = 0;
        if ( m.prot == (PF_X | PF_R) )
        {
            flags = PROT_READ | PROT_EXEC;
        }
        else if ( m.prot == (PF_W | PF_R) )
        {
            flags = PROT_READ | PROT_WRITE;
        }
        else if ( m.prot ==  PF_R)
        {
            flags = PROT_READ ;
        }
        int r =
            mprotect((void*)((long)m.addr & ~(page_size - 1)), m.size, flags);

        if (r == -1)
        {
            throw std::runtime_error("Error: mprotect failed"); 
        }
    }
    return 0;
}

int Loader::prepare_exec(void* argv)
{
    // Remove dll and loader from arguments
    unsigned long *p_argc = 
        (unsigned long *)((char*)argv - sizeof(char*));

    unsigned long *new_p_argc = 
        (unsigned long *)((char*)argv + sizeof(char*));

    *new_p_argc = *p_argc - 2;

    // Loop over argv[]
    char* p_arg = (char*)new_p_argc + sizeof(char*);
    while (*(unsigned long*)p_arg)
    {
        p_arg += sizeof(char*);
    }
    
    // Loop over envp[]
    p_arg += sizeof(char*);
    while (*(unsigned long*)p_arg)
    {
        p_arg += sizeof(char*);
    }

    // Fix aux vectors with proper values
    std::vector<std::pair<int, unsigned long>> auxv_to_change =
    {
        {AT_PHDR, (unsigned long)this->bin_base + this->offset_phdr}, 
        {AT_PHNUM, this->phnum},
        {AT_ENTRY, (unsigned long)this->entry},
        {AT_BASE, (unsigned long)this->interp_base}
    };

    for (auto auxv: auxv_to_change)
    {
        // First auxv
        bool found = false;
        unsigned long* idx = (unsigned long*)((char *)p_arg + sizeof(char*));

        while (!found)
        {
            if (*idx == auxv.first) 
            {
                *(unsigned long *)((char*)idx + sizeof(char*)) = auxv.second;
                found = true;
            }
            idx = (unsigned long*)((char*)idx + 2 * sizeof(char*));
        }
    }

    return 0;     
}

int Loader::exec(void* argv)
{
    void* rip; 
    if (this->is_static)
    {
        rip = this->entry;
    }
    else 
    {
        rip = this->interp_entry;
    }

    // This should never return
    do_call((char*)argv + sizeof(char*), rip);
    return 0;
}

