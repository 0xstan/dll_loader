#ifndef LOADER_H
#define LOADER_H

#include <vector>
#include <filesystem>

struct Memory
{
    void* addr;
    unsigned long size;
    unsigned long file_size;
    unsigned long offset;
    unsigned int prot;
};

class Loader 
{
    public:
        // Path of the library we want to inject
        std::filesystem::path lib_path;

        // Path of the binary we want to run 
        std::filesystem::path bin_path;

        // Path of the interpreter found in binary 
        std::filesystem::path interp_path;

        // Binary bytes
        std::vector<uint8_t> bin_b;

        // Binary loads segments
        std::vector<struct Memory> pt_loads;

        // Binary base address
        void *bin_base;

        // Interpreter base address
        void *interp_base;

        // Binary entry point
        void* entry;
        
        // interp entry point
        void* interp_entry;

        // Number of segments in binary
        int phnum;
        
        // Offset of phdr in binary
        int offset_phdr;

        // Is binary pie 
        bool is_pie;

        // Is binary static ( no interp !)
        bool is_static;

        Loader(std::string bin_path, std::string lib_path)
        {
            this->lib_path = std::filesystem::path(lib_path);
            this->bin_path = std::filesystem::path(bin_path);
        }

        // Read bin from disk and fill bin_b
        int read_bin();

        // Fill all the class members by reading ELF headers
        int parse_headers();

        // Map binary in memory with proper access rights
        int map_bin();
        
        // Load library in memory
        int load_lib();

        // Map interpreter in memory with proper access rights
        int map_interp();

        // Prepare exec by setting proper values in aux vectors
        int prepare_exec(void*);

        // Run the interpreter or the binary
        int exec(void*);
};

#endif
