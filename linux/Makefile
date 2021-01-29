CC=g++-8
CFLAGS=-std=c++17 -g
LFLAGS=-ldl -lstdc++fs

loader: helper.S entry.cpp loader.cpp
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

loader32: entry.cpp loader.cpp helper.S
	$(CC) $(CFLAGS) -m32 $^ -o $@ $(LFLAGS)
clean:
	rm loader loader32
