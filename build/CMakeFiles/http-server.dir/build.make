# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.6

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Produce verbose output by default.
VERBOSE = 1

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lindianyin/libevent

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lindianyin/libevent/build

# Include any dependencies generated for this target.
include CMakeFiles/http-server.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/http-server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/http-server.dir/flags.make

CMakeFiles/http-server.dir/sample/http-server.c.o: CMakeFiles/http-server.dir/flags.make
CMakeFiles/http-server.dir/sample/http-server.c.o: ../sample/http-server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lindianyin/libevent/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/http-server.dir/sample/http-server.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/http-server.dir/sample/http-server.c.o   -c /home/lindianyin/libevent/sample/http-server.c

CMakeFiles/http-server.dir/sample/http-server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/http-server.dir/sample/http-server.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lindianyin/libevent/sample/http-server.c > CMakeFiles/http-server.dir/sample/http-server.c.i

CMakeFiles/http-server.dir/sample/http-server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/http-server.dir/sample/http-server.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lindianyin/libevent/sample/http-server.c -o CMakeFiles/http-server.dir/sample/http-server.c.s

CMakeFiles/http-server.dir/sample/http-server.c.o.requires:

.PHONY : CMakeFiles/http-server.dir/sample/http-server.c.o.requires

CMakeFiles/http-server.dir/sample/http-server.c.o.provides: CMakeFiles/http-server.dir/sample/http-server.c.o.requires
	$(MAKE) -f CMakeFiles/http-server.dir/build.make CMakeFiles/http-server.dir/sample/http-server.c.o.provides.build
.PHONY : CMakeFiles/http-server.dir/sample/http-server.c.o.provides

CMakeFiles/http-server.dir/sample/http-server.c.o.provides.build: CMakeFiles/http-server.dir/sample/http-server.c.o


# Object files for target http-server
http__server_OBJECTS = \
"CMakeFiles/http-server.dir/sample/http-server.c.o"

# External object files for target http-server
http__server_EXTERNAL_OBJECTS =

bin/http-server: CMakeFiles/http-server.dir/sample/http-server.c.o
bin/http-server: CMakeFiles/http-server.dir/build.make
bin/http-server: lib/libevent_extra.a
bin/http-server: /usr/lib64/libssl.so
bin/http-server: /usr/lib64/libcrypto.so
bin/http-server: /usr/lib64/libz.so
bin/http-server: CMakeFiles/http-server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lindianyin/libevent/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable bin/http-server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/http-server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/http-server.dir/build: bin/http-server

.PHONY : CMakeFiles/http-server.dir/build

CMakeFiles/http-server.dir/requires: CMakeFiles/http-server.dir/sample/http-server.c.o.requires

.PHONY : CMakeFiles/http-server.dir/requires

CMakeFiles/http-server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/http-server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/http-server.dir/clean

CMakeFiles/http-server.dir/depend:
	cd /home/lindianyin/libevent/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lindianyin/libevent /home/lindianyin/libevent /home/lindianyin/libevent/build /home/lindianyin/libevent/build /home/lindianyin/libevent/build/CMakeFiles/http-server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/http-server.dir/depend

