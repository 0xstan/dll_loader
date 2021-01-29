#include <iostream>

#include "loader.hpp"

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cout << "usage: " <<  argv[0] << 
            " dll_to_inject binary ARGS" << std::endl; 
    }

    Loader l(argv[2], argv[1]);
    l.read_bin();
    l.parse_headers();
    l.map_bin();
    l.load_lib();

    if ( !l.is_static )
    {
        l.map_interp();
    }

    l.prepare_exec(argv);
    l.exec(argv);

    return 0;
}
