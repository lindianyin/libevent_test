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
include CMakeFiles/test-eof.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/test-eof.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test-eof.dir/flags.make

CMakeFiles/test-eof.dir/test/test-eof.c.o: CMakeFiles/test-eof.dir/flags.make
CMakeFiles/test-eof.dir/test/test-eof.c.o: ../test/test-eof.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lindianyin/libevent/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/test-eof.dir/test/test-eof.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test-eof.dir/test/test-eof.c.o   -c /home/lindianyin/libevent/test/test-eof.c

CMakeFiles/test-eof.dir/test/test-eof.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test-eof.dir/test/test-eof.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lindianyin/libevent/test/test-eof.c > CMakeFiles/test-eof.dir/test/test-eof.c.i

CMakeFiles/test-eof.dir/test/test-eof.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test-eof.dir/test/test-eof.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lindianyin/libevent/test/test-eof.c -o CMakeFiles/test-eof.dir/test/test-eof.c.s

CMakeFiles/test-eof.dir/test/test-eof.c.o.requires:

.PHONY : CMakeFiles/test-eof.dir/test/test-eof.c.o.requires

CMakeFiles/test-eof.dir/test/test-eof.c.o.provides: CMakeFiles/test-eof.dir/test/test-eof.c.o.requires
	$(MAKE) -f CMakeFiles/test-eof.dir/build.make CMakeFiles/test-eof.dir/test/test-eof.c.o.provides.build
.PHONY : CMakeFiles/test-eof.dir/test/test-eof.c.o.provides

CMakeFiles/test-eof.dir/test/test-eof.c.o.provides.build: CMakeFiles/test-eof.dir/test/test-eof.c.o


# Object files for target test-eof
test__eof_OBJECTS = \
"CMakeFiles/test-eof.dir/test/test-eof.c.o"

# External object files for target test-eof
test__eof_EXTERNAL_OBJECTS =

bin/test-eof: CMakeFiles/test-eof.dir/test/test-eof.c.o
bin/test-eof: CMakeFiles/test-eof.dir/build.make
bin/test-eof: lib/libevent_extra.a
bin/test-eof: CMakeFiles/test-eof.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lindianyin/libevent/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable bin/test-eof"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test-eof.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test-eof.dir/build: bin/test-eof

.PHONY : CMakeFiles/test-eof.dir/build

CMakeFiles/test-eof.dir/requires: CMakeFiles/test-eof.dir/test/test-eof.c.o.requires

.PHONY : CMakeFiles/test-eof.dir/requires

CMakeFiles/test-eof.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test-eof.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test-eof.dir/clean

CMakeFiles/test-eof.dir/depend:
	cd /home/lindianyin/libevent/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lindianyin/libevent /home/lindianyin/libevent /home/lindianyin/libevent/build /home/lindianyin/libevent/build /home/lindianyin/libevent/build/CMakeFiles/test-eof.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test-eof.dir/depend

