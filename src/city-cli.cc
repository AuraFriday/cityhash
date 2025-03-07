// Copyright (c) 2011 Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "city.h"
#ifdef __SSE4_2__
#include "citycrc.h"
#endif

using namespace std;

// Buffer size for reading files
const size_t BUFFER_SIZE = 8192;

// Enum for hash types
enum HashType {
  HASH_32,
  HASH_64,
  HASH_128,
  HASH_128CRC,
  HASH_256CRC
};

// Function to convert hash to hex string
template <typename T>
string HashToHex(const T& hash) {
  stringstream ss;
  ss << hex << setfill('0');
  
  // Handle uint32 and uint64 directly
  if (sizeof(T) <= 8) {
    ss << setw(sizeof(T) * 2) << hash;
  }
  
  return ss.str();
}

// Specialization for uint128
string HashToHex(const uint128& hash) {
  stringstream ss;
  ss << hex << setfill('0');
  ss << setw(16) << Uint128High64(hash) << setw(16) << Uint128Low64(hash);
  return ss.str();
}

// Function to hash a file or stdin
string HashFile(const string& filename, HashType hash_type) {
  FILE* file = nullptr;
  vector<char> buffer(BUFFER_SIZE);
  size_t bytes_read = 0;
  vector<char> content;
  
  // Open file or use stdin
  if (filename == "-") {
    file = stdin;
  } else {
    file = fopen(filename.c_str(), "rb");
    if (!file) {
      cerr << "Error: Cannot open file " << filename << endl;
      return "";
    }
  }
  
  // Read file into buffer
  while ((bytes_read = fread(buffer.data(), 1, BUFFER_SIZE, file)) > 0) {
    content.insert(content.end(), buffer.data(), buffer.data() + bytes_read);
  }
  
  // Close file if not stdin
  if (filename != "-") {
    fclose(file);
  }
  
  // Calculate hash based on type
  switch (hash_type) {
    case HASH_32: {
      uint32 hash = CityHash32(content.data(), content.size());
      return HashToHex(hash);
    }
    case HASH_64: {
      uint64 hash = CityHash64(content.data(), content.size());
      return HashToHex(hash);
    }
    case HASH_128: {
      uint128 hash = CityHash128(content.data(), content.size());
      return HashToHex(hash);
    }
#ifdef __SSE4_2__
    case HASH_128CRC: {
      uint128 hash = CityHashCrc128(content.data(), content.size());
      return HashToHex(hash);
    }
    case HASH_256CRC: {
      uint64 hash[4];
      CityHashCrc256(content.data(), content.size(), hash);
      stringstream ss;
      ss << hex << setfill('0');
      for (int i = 0; i < 4; i++) {
        ss << setw(16) << hash[i];
      }
      return ss.str();
    }
#endif
    default:
      return "";
  }
}

// Print usage information
void PrintUsage(const char* program_name) {
  cerr << "Usage: " << program_name << " [OPTION] [FILE]..." << endl;
  cerr << "Print CityHash checksums for each FILE." << endl;
  cerr << "With no FILE, or when FILE is -, read standard input." << endl;
  cerr << endl;
  cerr << "Options:" << endl;
  cerr << "  --32      use CityHash32 (32-bit)" << endl;
  cerr << "  --64      use CityHash64 (64-bit, default)" << endl;
  cerr << "  --128     use CityHash128 (128-bit)" << endl;
#ifdef __SSE4_2__
  cerr << "  --128c    use CityHashCrc128 (128-bit with CRC32 instruction)" << endl;
  cerr << "  --256c    use CityHashCrc256 (256-bit with CRC32 instruction)" << endl;
#endif
  cerr << "  --help    display this help and exit" << endl;
}

int main(int argc, char** argv) {
  HashType hash_type = HASH_64; // Default to 64-bit hash
  vector<string> files;
  
  // Parse command line arguments
  for (int i = 1; i < argc; i++) {
    string arg = argv[i];
    
    if (arg == "--help") {
      PrintUsage(argv[0]);
      return 0;
    } else if (arg == "--32") {
      hash_type = HASH_32;
    } else if (arg == "--64") {
      hash_type = HASH_64;
    } else if (arg == "--128") {
      hash_type = HASH_128;
    } 
#ifdef __SSE4_2__
    else if (arg == "--128c") {
      hash_type = HASH_128CRC;
    } else if (arg == "--256c") {
      hash_type = HASH_256CRC;
    }
#endif
    else {
      // Assume it's a filename
      files.push_back(arg);
    }
  }
  
  // If no files specified, use stdin
  if (files.empty()) {
    files.push_back("-");
  }
  
  // Process each file
  for (const auto& file : files) {
    string hash = HashFile(file, hash_type);
    if (!hash.empty()) {
      cout << hash << "  " << file << endl;
    } else {
      return 1; // Error occurred
    }
  }
  
  return 0;
} 