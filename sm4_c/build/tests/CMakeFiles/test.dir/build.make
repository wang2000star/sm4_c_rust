# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/wfz/sm4_pro/sm4_c

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/wfz/sm4_pro/sm4_c/build

# Include any dependencies generated for this target.
include tests/CMakeFiles/test.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include tests/CMakeFiles/test.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/test.dir/flags.make

tests/CMakeFiles/test.dir/test.c.o: tests/CMakeFiles/test.dir/flags.make
tests/CMakeFiles/test.dir/test.c.o: ../tests/test.c
tests/CMakeFiles/test.dir/test.c.o: tests/CMakeFiles/test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wfz/sm4_pro/sm4_c/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/CMakeFiles/test.dir/test.c.o"
	cd /home/wfz/sm4_pro/sm4_c/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT tests/CMakeFiles/test.dir/test.c.o -MF CMakeFiles/test.dir/test.c.o.d -o CMakeFiles/test.dir/test.c.o -c /home/wfz/sm4_pro/sm4_c/tests/test.c

tests/CMakeFiles/test.dir/test.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test.dir/test.c.i"
	cd /home/wfz/sm4_pro/sm4_c/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/wfz/sm4_pro/sm4_c/tests/test.c > CMakeFiles/test.dir/test.c.i

tests/CMakeFiles/test.dir/test.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test.dir/test.c.s"
	cd /home/wfz/sm4_pro/sm4_c/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/wfz/sm4_pro/sm4_c/tests/test.c -o CMakeFiles/test.dir/test.c.s

# Object files for target test
test_OBJECTS = \
"CMakeFiles/test.dir/test.c.o"

# External object files for target test
test_EXTERNAL_OBJECTS =

tests/test: tests/CMakeFiles/test.dir/test.c.o
tests/test: tests/CMakeFiles/test.dir/build.make
tests/test: libSymmetric.a
tests/test: tests/CMakeFiles/test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/wfz/sm4_pro/sm4_c/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable test"
	cd /home/wfz/sm4_pro/sm4_c/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/test.dir/build: tests/test
.PHONY : tests/CMakeFiles/test.dir/build

tests/CMakeFiles/test.dir/clean:
	cd /home/wfz/sm4_pro/sm4_c/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/test.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test.dir/clean

tests/CMakeFiles/test.dir/depend:
	cd /home/wfz/sm4_pro/sm4_c/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/wfz/sm4_pro/sm4_c /home/wfz/sm4_pro/sm4_c/tests /home/wfz/sm4_pro/sm4_c/build /home/wfz/sm4_pro/sm4_c/build/tests /home/wfz/sm4_pro/sm4_c/build/tests/CMakeFiles/test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test.dir/depend

