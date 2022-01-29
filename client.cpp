#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <fstream>

using namespace std;






/*
    sha1.hpp - source code of

    ============
    SHA-1 in C++
    ============

    100% Public Domain.

    Original C Code
        -- Steve Reid <steve@edmweb.com>
    Small changes to fit into bglibs
        -- Bruce Guenter <bruce@untroubled.org>
    Translation to simpler C++ Code
        -- Volker Diels-Grabsch <v@njh.eu>
    Safety fixes
        -- Eugene Hopkinson <slowriot at voxelstorm dot com>
    Header-only library
        -- Zlatko Michailov <zlatko@michailov.org>
*/

#ifndef SHA1_HPP
#define SHA1_HPP


#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>


class SHA1
{
public:
    SHA1();
    void update(const std::string &s);
    void update(std::istream &is);
    std::string final();
    static std::string from_file(const std::string &filename);

private:
    uint32_t digest[5];
    std::string buffer;
    uint64_t transforms;
};


static const size_t BLOCK_INTS = 16;  /* number of 32bit integers per SHA1 block */
static const size_t BLOCK_BYTES = BLOCK_INTS * 4;


inline static void reset(uint32_t digest[], std::string &buffer, uint64_t &transforms)
{
    /* SHA1 initialization constants */
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;

    /* Reset counters */
    buffer = "";
    transforms = 0;
}


inline static uint32_t rol(const uint32_t value, const size_t bits)
{
    return (value << bits) | (value >> (32 - bits));
}


inline static uint32_t blk(const uint32_t block[BLOCK_INTS], const size_t i)
{
    return rol(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i], 1);
}


/*
 * (R0+R1), R2, R3, R4 are the different operations used in SHA1
 */

inline static void R0(const uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    z += ((w&(x^y))^y) + block[i] + 0x5a827999 + rol(v, 5);
    w = rol(w, 30);
}


inline static void R1(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    block[i] = blk(block, i);
    z += ((w&(x^y))^y) + block[i] + 0x5a827999 + rol(v, 5);
    w = rol(w, 30);
}


inline static void R2(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    block[i] = blk(block, i);
    z += (w^x^y) + block[i] + 0x6ed9eba1 + rol(v, 5);
    w = rol(w, 30);
}


inline static void R3(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    block[i] = blk(block, i);
    z += (((w|x)&y)|(w&x)) + block[i] + 0x8f1bbcdc + rol(v, 5);
    w = rol(w, 30);
}


inline static void R4(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    block[i] = blk(block, i);
    z += (w^x^y) + block[i] + 0xca62c1d6 + rol(v, 5);
    w = rol(w, 30);
}


/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */

inline static void transform(uint32_t digest[], uint32_t block[BLOCK_INTS], uint64_t &transforms)
{
    /* Copy digest[] to working vars */
    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];
    uint32_t e = digest[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(block, a, b, c, d, e,  0);
    R0(block, e, a, b, c, d,  1);
    R0(block, d, e, a, b, c,  2);
    R0(block, c, d, e, a, b,  3);
    R0(block, b, c, d, e, a,  4);
    R0(block, a, b, c, d, e,  5);
    R0(block, e, a, b, c, d,  6);
    R0(block, d, e, a, b, c,  7);
    R0(block, c, d, e, a, b,  8);
    R0(block, b, c, d, e, a,  9);
    R0(block, a, b, c, d, e, 10);
    R0(block, e, a, b, c, d, 11);
    R0(block, d, e, a, b, c, 12);
    R0(block, c, d, e, a, b, 13);
    R0(block, b, c, d, e, a, 14);
    R0(block, a, b, c, d, e, 15);
    R1(block, e, a, b, c, d,  0);
    R1(block, d, e, a, b, c,  1);
    R1(block, c, d, e, a, b,  2);
    R1(block, b, c, d, e, a,  3);
    R2(block, a, b, c, d, e,  4);
    R2(block, e, a, b, c, d,  5);
    R2(block, d, e, a, b, c,  6);
    R2(block, c, d, e, a, b,  7);
    R2(block, b, c, d, e, a,  8);
    R2(block, a, b, c, d, e,  9);
    R2(block, e, a, b, c, d, 10);
    R2(block, d, e, a, b, c, 11);
    R2(block, c, d, e, a, b, 12);
    R2(block, b, c, d, e, a, 13);
    R2(block, a, b, c, d, e, 14);
    R2(block, e, a, b, c, d, 15);
    R2(block, d, e, a, b, c,  0);
    R2(block, c, d, e, a, b,  1);
    R2(block, b, c, d, e, a,  2);
    R2(block, a, b, c, d, e,  3);
    R2(block, e, a, b, c, d,  4);
    R2(block, d, e, a, b, c,  5);
    R2(block, c, d, e, a, b,  6);
    R2(block, b, c, d, e, a,  7);
    R3(block, a, b, c, d, e,  8);
    R3(block, e, a, b, c, d,  9);
    R3(block, d, e, a, b, c, 10);
    R3(block, c, d, e, a, b, 11);
    R3(block, b, c, d, e, a, 12);
    R3(block, a, b, c, d, e, 13);
    R3(block, e, a, b, c, d, 14);
    R3(block, d, e, a, b, c, 15);
    R3(block, c, d, e, a, b,  0);
    R3(block, b, c, d, e, a,  1);
    R3(block, a, b, c, d, e,  2);
    R3(block, e, a, b, c, d,  3);
    R3(block, d, e, a, b, c,  4);
    R3(block, c, d, e, a, b,  5);
    R3(block, b, c, d, e, a,  6);
    R3(block, a, b, c, d, e,  7);
    R3(block, e, a, b, c, d,  8);
    R3(block, d, e, a, b, c,  9);
    R3(block, c, d, e, a, b, 10);
    R3(block, b, c, d, e, a, 11);
    R4(block, a, b, c, d, e, 12);
    R4(block, e, a, b, c, d, 13);
    R4(block, d, e, a, b, c, 14);
    R4(block, c, d, e, a, b, 15);
    R4(block, b, c, d, e, a,  0);
    R4(block, a, b, c, d, e,  1);
    R4(block, e, a, b, c, d,  2);
    R4(block, d, e, a, b, c,  3);
    R4(block, c, d, e, a, b,  4);
    R4(block, b, c, d, e, a,  5);
    R4(block, a, b, c, d, e,  6);
    R4(block, e, a, b, c, d,  7);
    R4(block, d, e, a, b, c,  8);
    R4(block, c, d, e, a, b,  9);
    R4(block, b, c, d, e, a, 10);
    R4(block, a, b, c, d, e, 11);
    R4(block, e, a, b, c, d, 12);
    R4(block, d, e, a, b, c, 13);
    R4(block, c, d, e, a, b, 14);
    R4(block, b, c, d, e, a, 15);

    /* Add the working vars back into digest[] */
    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;

    /* Count the number of transformations */
    transforms++;
}


inline static void buffer_to_block(const std::string &buffer, uint32_t block[BLOCK_INTS])
{
    /* Convert the std::string (byte buffer) to a uint32_t array (MSB) */
    for (size_t i = 0; i < BLOCK_INTS; i++)
    {
        block[i] = (buffer[4*i+3] & 0xff)
                   | (buffer[4*i+2] & 0xff)<<8
                   | (buffer[4*i+1] & 0xff)<<16
                   | (buffer[4*i+0] & 0xff)<<24;
    }
}


inline SHA1::SHA1()
{
    reset(digest, buffer, transforms);
}


inline void SHA1::update(const std::string &s)
{
    std::istringstream is(s);
    update(is);
}


inline void SHA1::update(std::istream &is)
{
    while (true)
    {
        char sbuf[BLOCK_BYTES];
        is.read(sbuf, BLOCK_BYTES - buffer.size());
        buffer.append(sbuf, (std::size_t)is.gcount());
        if (buffer.size() != BLOCK_BYTES)
        {
            return;
        }
        uint32_t block[BLOCK_INTS];
        buffer_to_block(buffer, block);
        transform(digest, block, transforms);
        buffer.clear();
    }
}


/*
 * Add padding and return the message digest.
 */

inline std::string SHA1::final()
{
    /* Total number of hashed bits */
    uint64_t total_bits = (transforms*BLOCK_BYTES + buffer.size()) * 8;

    /* Padding */
    buffer += (char)0x80;
    size_t orig_size = buffer.size();
    while (buffer.size() < BLOCK_BYTES)
    {
        buffer += (char)0x00;
    }

    uint32_t block[BLOCK_INTS];
    buffer_to_block(buffer, block);

    if (orig_size > BLOCK_BYTES - 8)
    {
        transform(digest, block, transforms);
        for (size_t i = 0; i < BLOCK_INTS - 2; i++)
        {
            block[i] = 0;
        }
    }

    /* Append total_bits, split this uint64_t into two uint32_t */
    block[BLOCK_INTS - 1] = (uint32_t)total_bits;
    block[BLOCK_INTS - 2] = (uint32_t)(total_bits >> 32);
    transform(digest, block, transforms);

    /* Hex std::string */
    std::ostringstream result;
    for (size_t i = 0; i < sizeof(digest) / sizeof(digest[0]); i++)
    {
        result << std::hex << std::setfill('0') << std::setw(8);
        result << digest[i];
    }

    /* Reset for next run */
    reset(digest, buffer, transforms);

    return result.str();
}


inline std::string SHA1::from_file(const std::string &filename)
{
    std::ifstream stream(filename.c_str(), std::ios::binary);
    SHA1 checksum;
    checksum.update(stream);
    return checksum.final();
}


#endif /* SHA1_HPP */

















struct FileStruct
{
    vector<bool> FileChunks;
    long long num_chunks;
    string filePath;
    string fileName;
    long long Filesize;
    string SHA;
};

#define CHUNK 512000
#define FILE_SEG_SIZE 524288
string currentTrackerIP, tracker_ip1, tracker_ip2, peer_IP;
uint16_t currentTrackerPORT, tracker_port1, tracker_port2, peer_PORT;
bool isActive=false;
unordered_map<string, unordered_map<string, bool>> uploadedFiles;
unordered_map<string, string> NameToPath;
unordered_map<string, string> FileToChunks;
unordered_map<string, vector<bool>> FileChunkVec;
unordered_map<string, vector<string>> downloaded_Files;
unordered_map<string, FileStruct> FileDetails;
vector<vector<string>> currentDownloadFileChunks;

long long file_size(char *path)
{
    FILE *fp = fopen(path, "rb");

    long size = -1;
    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        size = ftell(fp) + 1;
        std::fclose(fp);
    }
    else
    {
        printf("File not found.\n");
        return -1;
    }
    return size;
}

vector<string> split(string str, char del)
{
    string temp = "";
    vector<string> ans;
    for (int i = 0; i < (int)str.size() - 1; i++)
    {
        if (str[i] != del)
        {
            temp += str[i];
        }
        else
        {
            ans.push_back(temp);
            temp = "";
        }
    }
    if (temp.size() > 0)
        ans.push_back(temp);
    return ans;
}

int TrackerConnect(int trackernum, struct sockaddr_in &serv_addr, int sockfd)
{
    std::cout << "[+]Trying to connect with tracker" << endl;
    char *currentTrackerIP;
    uint16_t currentTrackerPORT;
    if (trackernum == 2)
    {
        currentTrackerIP = &tracker_ip2[0];
        currentTrackerPORT = tracker_port2;
    }
    if (trackernum == 1)
    {
        currentTrackerIP = &tracker_ip1[0];
        currentTrackerPORT = tracker_port1;
    }
    bool error = false;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(currentTrackerPORT);
    if (inet_pton(AF_INET, currentTrackerIP, &serv_addr.sin_addr) <= 0)
    {
        error = true;
        perror(" error");
    }
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        error = true;
        perror("connect error");
    }
   
    if (error)
    {
        if (trackernum == 1)
        {
            std::cout << "trying" << endl;
            return TrackerConnect(2, serv_addr, sockfd);
        }
        else
        {
            return -1;
        }
    }
    return 0;
}

void handle_client_client(int client_socket)
{
    string client_uid = "";

    char inptline[1024] = {0};

    if (read(client_socket, inptline, 1024) <= 0)
    {
        close(client_socket);
        perror("HCC read:");
        return;
    }

    vector<string> inpt = split(string(inptline), '%');

    if (inpt[0] == "get_chunk")
    {
        // inpt = [get_chunk, filename, to_string(chunkNum), destination,filesize,totalchunks]
        string fileName = inpt[1];
        string filepath = FileDetails[fileName].filePath;
        long long chunkNum = stoll(inpt[2]);
        long long total_chunks = stoll(inpt.back());
        long long filesize = stoll(inpt[4]);
        string dest_path = inpt[3];
        // cout << "call get_chunk" << endl;
        // file read and send
        FILE *fp = fopen(filepath.c_str(), "r");
        //cout<<"reading from"<<filepath<<endl;
        if (fp)
        {
            int chunk_size = FILE_SEG_SIZE;
            bool last_chunk = false;
            if (chunkNum + 1 == total_chunks)
            {
                chunk_size = filesize % FILE_SEG_SIZE;
                last_chunk = true;
            }
            fseek(fp, chunkNum * FILE_SEG_SIZE, SEEK_SET);
            size_t size;
            long long FS = file_size(&filepath[0]);
            // std::cout << "file size: " << FS << endl;
            // long long left_chunk = FS % FILE_SEG_SIZE;
            long long chunks = FS / FILE_SEG_SIZE;
            char data[chunk_size] = {0};
            if ((size = fread(data, 1, FILE_SEG_SIZE, fp)) > 0)
            {
                // std::cout << strlen(data) << endl;
                send(client_socket, data, size, 0);
                memset(data, 0, sizeof(data));
                fclose(fp);
            }
            else if (last_chunk)
            {
                size = fread(data, 1, chunk_size, fp);
                send(client_socket, data, size, 0);
                memset(data, 0, sizeof(data));
                fclose(fp);
            }
            //  cout<<"data sent: "<<size<<endl;
        }
        else
        {
            write(client_socket, "Error while reading file", 24);
            fclose(fp);
        }
        //  write(client_socket, "done", 4);
        // fclose(fp);
    }
    else if (inpt[0] == "get_file_path_sha")
    {
        string filepath = FileDetails[inpt[1]].filePath;
        filepath = filepath+ "%"+ FileDetails[inpt[1]].SHA+"%";
        write(client_socket, &filepath[0], strlen(filepath.c_str()));
    }
    close(client_socket);
    return;
}

// void *server(void *arg)
void server()
{

    int server_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int setSocketOpt = 1;

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &setSocketOpt, sizeof(setSocketOpt)))
    {
        perror("setsockopt error:");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_port = htons(peer_PORT);

    if (inet_pton(AF_INET, &peer_IP[0], &address.sin_addr) <= 0)
    {
        printf("\nInvalid address/ Address not supported \n");
        // return NULL;
    }

    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    vector<thread> vec_threads;
    while (true)
    {

        int client_socket;

        if ((client_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        {
            perror("Acceptance error");
        }

        vec_threads.push_back(thread(handle_client_client, client_socket));
        //  vThread.back().detach();
    }
    for (auto it = vec_threads.begin(); it != vec_threads.end(); it++)
    {
        //    if(it->joinable()) it->join();
        it->detach();
    }
    vec_threads.clear();
    close(server_socket);
}

string connectToPeer(char *port, string command_str)
{
    // command =
    //  cout << "trying to connect with: " << string(port) << endl;
    int peersockfd = 0;
    struct sockaddr_in peer_serv_addr;

    if ((peersockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return "error";
    }

    peer_serv_addr.sin_family = AF_INET;
    uint16_t peerPort = stoi(string(port));
    peer_serv_addr.sin_port = htons(peerPort);

    if (inet_pton(AF_INET, &peer_IP[0], &peer_serv_addr.sin_addr) < 0)
    {
        perror("Peer Connecion Error(INET)");
    }
    if (connect(peersockfd, (struct sockaddr *)&peer_serv_addr, sizeof(peer_serv_addr)) < 0)
    {
        perror("Peer Connection Errorr");
    }

    vector<string> temp = split(command_str, '%');

    if (temp[0] == "get_chunk")
    {
        //"get_chunk  filename  to_string(chunkNum)  destination filesize totalchunks
        if (send(peersockfd, &command_str[0], strlen(&command_str[0]), MSG_NOSIGNAL) == -1)
        {
            printf("Error: %s\n", strerror(errno));
            return "error";
        }

        // writing into file from server
        string fileName = temp[1];
        long long chunkNum = stoll(temp[2]);
        string filepath = temp[3];
        long long filesize = stoll(temp[4]);
        long long total_chunks = stoll(temp[5]);
        int chunk_size = FILE_SEG_SIZE;
        if (total_chunks - 1 == chunkNum)
        {
            chunk_size = filesize % FILE_SEG_SIZE;
        }
        // writing
        FILE *fd = fopen(temp[3].c_str(), "r+");

        if (fd)
        {
            size_t size;
            char buff[chunk_size] = {0};
            long offset = chunkNum * FILE_SEG_SIZE;
            fseek(fd, offset, SEEK_SET);
            int s;
            while ((size = recv(peersockfd, buff, chunk_size, 0)) > 0)
            {
                fwrite(buff, 1, size, fd);
                memset(buff, 0, sizeof(buff));
                // cout<<"data bytes recv: "<<size<<endl;
            }
        }
        else
        {
            cout << "file write error" << endl;
        }
        fclose(fd);
    }
    else if (temp[0] == "get_file_path_sha")
    {
        // "get_file_path_sha%" + filename + "%";
        vector<string> temp = split(command_str, '%');
        string fileName = temp.back();
        if (send(peersockfd, command_str.c_str(), strlen(command_str.c_str()), MSG_NOSIGNAL) == -1)
        {
            printf("Error: %s\n", strerror(errno));
            return "error";
        }
        char server_reply[10240] = {0};
        if (read(peersockfd, server_reply, 10240) < 0)
        {
            perror("err: ");
            return "error";
        }
        close(peersockfd);
        return string(server_reply);
       // vector<string> path_sha = split(string(server_reply),'%');
      //  FileDetails[fileName].filePath = path_sha[0];

    }
    close(peersockfd);
    return "fishy";
}

void getChunk(string str)
{

    // fileName  (randompeer) to_string(randompiece) dest_path  "filsize" tot_chunks
    try
    {
        vector<string> temp = split(str, '%');
        string filename = temp[0];
        string port = temp[1];
        long long chunkNum = stoll(temp[2]);
        string destination = temp[3];
        string filesize = temp[4];
        string total_chunks = temp[5];
        string command = "get_chunk%" + filename + "%" + to_string(chunkNum) + "%" + destination + "%" + filesize + "%" + total_chunks + "%";
        connectToPeer(&port[0], command);
    }
    catch (char *e)
    {
        cout << "ex:" << string(e) << endl;
    }
    return;
}

void download(vector<string> inpt_command, vector<string> peers)
{
    string dest_path = inpt_command[3] + "/" + inpt_command[2];
    FILE *fp = fopen(dest_path.c_str(), "r+");
    if (fp != 0)
    {
        cout << "The file is threre already" << endl;
        fclose(fp);
        return;
    }

    string gid = inpt_command[1];
    string fileName = inpt_command[2];
    long long filesize = stoll(peers.back());
    peers.pop_back();
    long long segments = ceil(float(filesize) / FILE_SEG_SIZE);

    FILE *des_fp = fopen(dest_path.c_str(), "a");
    fclose(des_fp);

    vector<thread> vec_threads;

    long long next_chunk = 0;
    long long num_peers = peers.size();
    string server_peer = peers.front();
    long long index_server_peer = 0;
    downloaded_Files[fileName].push_back("D");
    downloaded_Files[fileName].push_back(gid);
    while (next_chunk < segments)
    {
        server_peer = peers[index_server_peer % num_peers];
        index_server_peer++;

        string str = fileName + "%" + server_peer + "%" + to_string(next_chunk) + "%" + dest_path + "%" + to_string(filesize) + "%" + to_string(segments) + "%";
        cout << "chunk: " << next_chunk << " from port:" << server_peer << endl;
        vec_threads.push_back(thread(getChunk, str));
        next_chunk++;
    }
    for (auto it = vec_threads.begin(); it != vec_threads.end(); it++)
    {
        it->detach();
    }
    cout << "Downloaed successfully" << endl;

    downloaded_Files[fileName][0] = "C";
    FileDetails[fileName].filePath=dest_path;
   string path_sha= connectToPeer(&server_peer[0], "get_file_path_sha%" + fileName + "%");
    vector<string> path_sha_vec=split(path_sha,'%');
    string org_sha=path_sha_vec[1];
    string sha_val=SHA1::from_file(dest_path.c_str());
    if(org_sha == sha_val){
        cout<<"Downloaded succesfully and verified by SHA"<<endl<<endl;
    }else{
        cout<<"Downloade but SHA verification failed"<<endl<<endl;
    }
    FileDetails[fileName].SHA = sha_val;
    return;
}

int executeCommand(vector<string> input_line_vec, int sockfd)
{
    string command = input_line_vec[0];
    char ServerMsg[10240] = {0};
    bzero(ServerMsg,10240);
    if (command == "show_downloads")
    {
        if (input_line_vec.size() == 1)
        {
            cout<<endl;
            for (auto it = downloaded_Files.begin(); it != downloaded_Files.end(); it++)
            {
                string status = it->second[0];
                string fn = it->first;
                string gid = it->second[1];
                cout << "[" << status << "] [" << gid << "] " << fn << endl;
            }
            cout<<endl;
        }
        else
        {
            cout << "Invalid Command" << endl<<endl;
        }
        return 0;
    }
   else if (command == "stop_share")
    {
        if (input_line_vec.size() ==3)
        {
            string gid = input_line_vec[1];
            string filename=input_line_vec[2];
            string send_msg = gid +" "+filename+" ";
            write(sockfd,send_msg.c_str(),strlen(send_msg.c_str()));
        }
        else
        {
            cout << "Invalid Command" << endl<<endl;
            return 0;
        }
        bzero(ServerMsg,10240);
        read(sockfd, ServerMsg, 10240);
        string stop_share_reply = string(ServerMsg);
        cout<<stop_share_reply<<endl;
        return 0;
    }
    
    read(sockfd, ServerMsg, 10240);
    string msg = string(ServerMsg);

    if (msg == "Invalid command")
    {
        std::cout << msg << endl<<endl;
        return 0;
    }
    if (command == "login")
    {
        if (msg == "Login Successful")
        {
            std::cout <<endl<< msg << endl<<endl;
            isActive = true;
            // check it
            string clientAddress = to_string(peer_PORT);
            write(sockfd, &clientAddress[0], clientAddress.length());
        }
    }
    else if (command == "logout")
    {
        std::cout << msg << endl<<endl;
        isActive = false;
    }
    else if (command == "upload_file")
    {
        if (msg == "Invalid Group ID")
        {
            std::cout << "Invalid Group ID" << endl<<endl;
        }
        else if (msg == "Not a member")
        {
            std::cout << "Not a member" << endl<<endl;
        }
        else if (msg == "Invalid file path")
        {
            std::cout << "Invalid file path" << endl<<endl;
        }
        else
        {
            string path = input_line_vec[1];
            string fileName = split(path + "/", '/').back();
            string gid = input_line_vec[2];
            if (uploadedFiles[gid][fileName])
            {
                std::cout << endl<<"File already uploaded" << endl<<endl;
                // write(sockfd, "already uploaded", 16);
            }
            else
            {
                // read(sockfd, ServerMsg, 10240);

                uploadedFiles[gid][fileName] = true;
                // check it
                NameToPath[fileName] = string(path);
                FileDetails[fileName].filePath = string(path);
                long long FS = file_size(&path[0]);
                long long num_chunk = ceil(float(FS) / FILE_SEG_SIZE);

                FileDetails[fileName].fileName = fileName;
                FileDetails[fileName].Filesize = FS;
                string num_chunks = to_string(num_chunk);
                string uploaded_tracker_msg_1 = fileName;

                uploaded_tracker_msg_1 = uploaded_tracker_msg_1 + "%" + num_chunks;
                uploaded_tracker_msg_1 = uploaded_tracker_msg_1 + "%" + to_string(peer_PORT);
                uploaded_tracker_msg_1 = uploaded_tracker_msg_1 + "%" + to_string(FS);
                uploaded_tracker_msg_1 = uploaded_tracker_msg_1 + "%" + path + "%";

                FileToChunks[fileName] = num_chunks;
                FileDetails[fileName].num_chunks = num_chunk;
                string sha_val=SHA1::from_file(path.c_str());
                FileDetails[fileName].SHA=sha_val;
                write(sockfd, uploaded_tracker_msg_1.c_str(), uploaded_tracker_msg_1.length());
                cout <<endl<< "uploaded successfuly" << endl<<endl;
            }
        }
    }
    else if (command == "list_files")
    {
        string replyStr = msg;
        if (replyStr == "Invalid Group ID")
        {
            std::cout << "Invalid Group ID" << endl<<endl;
        }
        else if (replyStr == "You are not part of this group")
        {
            std::cout << replyStr << endl<<endl;
        }
        else if (replyStr == "No Files")
        {
            std::cout << "No files in this group" << endl<<endl;
        }
        else
        {
            char list_files_reply[102400];
            read(sockfd, list_files_reply, 102400);
            vector<string> list_files = split(string(list_files_reply), '%');

            std::cout << "Files: " << endl;
            for (string str : list_files)
            {
                std::cout << str << endl;
            }
        }
    }
    else if (command == "send")
    {

        FILE *fd = fopen(input_line_vec[2].c_str(), "w");

        if (fd)
        {
            size_t size;
            char buff[CHUNK] = {0};
            int s;
            while ((size = recv(sockfd, buff, CHUNK, 0)) > 0)
            {
                std::cout << buff << endl;
                if (string(buff) == "done")
                {
                    break;
                }
                else
                {
                    std::cout << "data" << endl;
                }
                fwrite(buff, 1, size, fd);
                memset(buff, 0, sizeof(buff));
            }
        }
        std::cout << "recv" << endl;
        std::fclose(fd);
    }
    else if (command == "download_file")
    {
        string reply = msg;
        if (reply == "Invalid Group ID")
        {
            std::cout << reply << endl<<endl;
        }
        else if (reply == "You are not part of this group")
        {
            std::cout << reply << endl<<endl;
        }
        else if (reply == "Invalid dest path")
        {
            std::cout << reply << endl<<endl;
        }
        else if (reply == "File not found")
        {
            std::cout << reply << endl<<endl;
        }
        else
        {
            // std::cout << "client file ports: " << reply << endl;
            vector<string> FilePORTS = split(reply, '%');
            if (FilePORTS.size() > 1)
            {
                download(input_line_vec, FilePORTS);
                string filename = "add_port_to_file ";
                filename = filename + input_line_vec[2];
                filename = filename + " " + to_string(peer_PORT) + " ";
                write(sockfd, filename.c_str(), strlen(filename.c_str()));
            }
            else
            {
                cout << "There are no active peers for this file now" << endl<<endl;
            }
        }
    }
    else if (command == "list_groups")
    {
        string reply = msg;
        if (string(reply) == "No groups")
        {
            std::cout << "There are no groups" << endl;
        }
        else
        {
            std::cout <<endl<< "Groups:" << endl;
            vector<string> groups = split(string(reply), '%');
            for (string g : groups)
            {
                std::cout << "group id: " << g << endl;
            }
            cout<<endl;
        }
    }
    else if (command == "list_requests")
    {

        string replyStr = msg;
        if (replyStr == "Invalid Group ID")
        {
            std::cout << "Invalid Group ID" << endl<<endl;
        }
        else if (replyStr == "You are not admin of this group")
        {
            std::cout << "You are not admin of this group" << endl<<endl;
        }
        else if (replyStr == "No requests")
        {
            std::cout << "No requests" << endl<<endl;
        }
        else
        {
            std::cout << "Pending reqs are: " << endl;
            vector<string> reqs = split(replyStr, '%');
            for (string r : reqs)
            {
                std::cout << "user id: " << r << endl;
            }
        }
    }
    else if (command == "accept_request")
    {

        std::cout << endl<< msg << endl<<endl;
    }
    else if (command == "leave_group")
    {

        std::cout << msg << endl<<endl;
    }

    

    else
    {
        bzero(ServerMsg,10240);
        std::cout << endl
                  << msg << endl<<endl;
                 
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cout << "invalid command" << endl;
        return 0;
    }

    string trackerFileName = argv[2];
    string peerIP_P = argv[1];
    int index = 0;
    while (1)
    {
        if (peerIP_P[index] == ':')
            break;
        index++;
    }
    peer_IP = peerIP_P.substr(0, index);
    peer_PORT = stoi(peerIP_P.substr(index + 1, peerIP_P.length() - index));
    fstream trackerInfoFile;
    trackerInfoFile.open(trackerFileName, ios::in);
    vector<string> trackerDetails;
    if (!trackerInfoFile.is_open())
    {
        std::cout << "Error while opening tracker info file" << endl;
        exit(0);
    }
    else
    {
        string str;
        while (getline(trackerInfoFile, str))
        {
            trackerDetails.push_back(str);
        }
        trackerInfoFile.close();
    }

    tracker_ip1 = trackerDetails[0];
    tracker_port1 = stoi(trackerDetails[1]);
    tracker_ip2 = trackerDetails[2];
    tracker_port2 = stoi(trackerDetails[3]);

    int sockfd;
    struct sockaddr_in serv_addr;
    pthread_t serverThread;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket create error");
        return 0;
    }

    // if (pthread_create(&serverThread, NULL, server, NULL) == -1)
    // {
    //     perror("error in server thread of client");
    //     return 0;
    // }
    thread t(server);
    t.detach();
    // t.join();
    //  pthread_join(serverThread,NULL);

    if (TrackerConnect(1, serv_addr, sockfd) < 0)
    {
        exit(0);
    }
    std::cout << "[+]Connected to tracker" << endl;
    while (1)
    {
        std::cout << "[+]enter your command:  " ;
        string input_line, str;
        getline(cin, input_line);

        stringstream ss(input_line);
        vector<string> input_line_vec;
        while (ss >> str)
        {
            input_line_vec.push_back(str);
        }
        string command = input_line_vec[0];
        if (command == "login")
        {
            if (isActive)
            {
                cout << "---->You are already logged in" << endl<<endl;
                continue;
            }
        }
        else if (command != "create_user" && !isActive)
        {
            cout << "---->Please create account or login" << endl<<endl;
            continue;
        }

        if (send(sockfd, &input_line[0], strlen(&input_line[0]), MSG_NOSIGNAL) == -1)
        {
            std::cout << "Error" << endl
                      << strerror(errno) << endl;
            return -1;
        }

        int rt = executeCommand(input_line_vec, sockfd);
    }
    close(sockfd);
    return 0;
}