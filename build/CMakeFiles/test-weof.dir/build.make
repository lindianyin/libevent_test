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
include CMakeFiles/test-weof.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/test-weof.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test-weof.dir/flags.make

CMakeFiles/test-weof.dir/test/test-weof.c.o: CMakeFiles/test-weof.dir/flags.make
CMakeFiles/test-weof.dir/test/test-weof.c.o: ../test/test-weof.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lindianyin/libevent/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/test-weof.dir/test/test-weof.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test-weof.dir/test/test-weof.c.o   -c /home/lindianyin/libevent/test/test-weof.c

CMakeFiles/test-weof.dir/test/test-weof.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test-weof.dir/test/test-weof.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lindianyin/libevent/test/test-weof.c > CMakeFiles/test-weof.dir/test/test-weof.c.i

CMakeFiles/test-weof.dir/test/test-weof.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test-weof.dir/test/test-weof.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lindianyin/libevent/test/test-weof.c -o CMakeFiles/test-weof.dir/test/test-weof.c.s

CMakeFiles/test-weof.dir/test/test-weof.c.o.requires:

.PHONY : CMakeFiles/test-weof.dir/test/test-weof.c.o.requires

CMakeFiles/test-weof.dir/test/test-weof.c.o.provides: CMakeFiles/test-weof.dir/test/test-weof.c.o.requires
	$(MAKE) -f CMakeFiles/test-weof.dir/build.make CMakeFiles/test-weof.dir/test/test-weof.c.o.provides.build
.PHONY : CMakeFiles/test-weof.dir/test/test-weof.c.o.provides

CMakeFiles/test-weof.dir/test/test-weof.c.o.provides.build: CMakeFiles/test-weof.dir/test/test-weof.c.o


# Object files for target test-weof
test__weof_OBJECTS = \
"CMakeFiles/test-weof.dir/test/test-weof.c.o"

# External object files for target test-weof
test__weof_EXTERNAL_OBJECTS =

bin/test-weof: CMakeFiles/test-weof.dir/test/test-weof.c.o
bin/test-weof: CMakeFiles/test-weof.dir/build.make
bin/test-weof: lib/libevent_extra.a
bin/test-weof: CMakeFiles/test-weof.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lindianyin/libevent/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable bin/test-weof"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test-weof.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test-weof.dir/build: bin/test-weof

.PHONY : CMakeFiles/test-weof.dir/build

CMakeFiles/test-weof.dir/requires: CMakeFiles/test-weof.dir/test/test-weof.c.o.requires

.PHONY : CMakeFiles/test-weof.dir/requires

CMakeFiles/test-weof.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test-weof.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test-weof.dir/clean

CMakeFiles/test-weof.dir/depend:
	cd /home/lindianyin/libevent/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lindianyin/libevent /home/lindianyin/libevent /home/lindianyin/libevent/build /home/lindianyin/libevent/build /home/lindianyin/libevent/build/CMakeFiles/test-weof.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test-weof.dir/depend

