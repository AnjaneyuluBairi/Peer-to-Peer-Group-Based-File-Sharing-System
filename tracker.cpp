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
using namespace std;
#define CHUNK 512000
#define SA struct sockaddr

string currentTrackerIP, tracker_ip1, tracker_ip2;
uint16_t currentTrackerPORT, tracker_port1, tracker_port2;

unordered_map<string, string> usersCreds;
unordered_map<string, bool> activeUsers;
vector<string> Groups;
unordered_map<string, string> GroupAdmins;
unordered_map<string, set<string>> GroupMembers;
unordered_map<string, set<string>> GroupPendingReqs;
unordered_map<string, string> UserIdAndPorts;
unordered_map<string, set<string>> portsToUserIDS;
// unordered_map<string, string> FileToChunks;
unordered_map<string, set<string>> FileNameToPort;
// unordered_map<string, unordered_map<string, set<string>>> FileNameToPort;
unordered_map<string, set<string>> GroupToFiles;
unordered_map<string, string> NameToPath;
unordered_map<string, string> FileToChunks;
unordered_map<string, set<string>> usersToFiles;

struct FileStruct
{
	vector<bool> FileChunks;
	long long num_chunks;
	string filePath;
	string fileName;
	long long Filesize;
	set<string> uploaded_users;
	unordered_map<string, set<string>> FGU;
};
string getFileDetails(struct FileStruct f)
{
	string str = f.fileName + "%" + f.filePath + "%" + to_string(f.Filesize) + "%" + to_string(f.num_chunks) + "%";
	return str;
}
void printFileDetails(struct FileStruct f)
{

	std::cout << "filename: " << f.fileName << endl;
	std::cout << "path: " << f.filePath << endl;
	std::cout << "size: " << f.Filesize << endl;
	std::cout << "chunks: " << f.num_chunks << endl;
	return;
}
unordered_map<string, FileStruct> FileDetails;

bool validpath(const string &s)
{
	struct stat buffer;
	return (stat(s.c_str(), &buffer) == 0);
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

void *checkQuit(void *arg)
{
	while (1)
	{
		string input;
		getline(cin, input);
		if (input == "quit")
		{
			exit(0);
		}
	}
}

long long file_size(char *path)
{
	FILE *fp = fopen(path, "rb");

	long size = -1;
	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		size = ftell(fp) + 1;
		fclose(fp);
	}
	else
	{
		printf("File not found.\n");
		return -1;
	}
	return size;
}

void *handle_client(void *d_clientSocket)
{
	int client_socket = *(int *)d_clientSocket;
	free(d_clientSocket);
	string client_userID = "";
	string client_groupID = "";

	while (1)
	{
		char input_line[1024] = {0};
		bzero(input_line,1024);
		if (read(client_socket, input_line, 1024) <= 0)
		{
			activeUsers[client_userID] = false;
			close(client_socket);
			break;
		}
		string str, InputLine = string(input_line);
		// std::cout << InputLine << endl;
		stringstream ss(InputLine);
		vector<string> input_line_vec;

		while (ss >> str)
		{
			input_line_vec.push_back(str);
		}

		string command = input_line_vec[0];
		// std::cout << "command: " << command << endl;
		if (command == "add_port_to_file")
		{
			string fileName = input_line_vec[1];
			string file_port = input_line_vec[2];
			FileNameToPort[fileName].insert(file_port);
		}
		else if (command == "create_user")
		{
			if (input_line_vec.size() != 3)
			{

				write(client_socket, "Invalid command", 15);
			}
			else
			{
				string uid = input_line_vec[1];
				string upwd = input_line_vec[2];
				if (usersCreds.find(uid) == usersCreds.end())
				{
					usersCreds.insert({uid, upwd});
					write(client_socket, "Account created", 15);
				}
				else
				{
					write(client_socket, "User already exists", 19);
				}
			}
		}
		else if (command == "login")
		{
			if (input_line_vec.size() != 3)
			{
				string resp_string = "Invalid command";
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				string uid = input_line_vec[1];
				string upwd = input_line_vec[2];

				if (usersCreds.find(uid) == usersCreds.end() || usersCreds[uid] != upwd)
				{
					write(client_socket, "Username/password incorrect", 28);
				}
				else if (activeUsers.find(uid) == activeUsers.end())
				{
					activeUsers.insert({uid, true});
					write(client_socket, "Login Successful", 16);
					// check it again
					client_userID = uid;
					char buf[1024];
					read(client_socket, buf, 96);
					UserIdAndPorts[client_userID] = string(buf);
					portsToUserIDS[string(buf)].insert(client_userID);
				}
				else
				{
					if (!activeUsers[uid])
					{
						activeUsers[uid] = true;
						write(client_socket, "Login Successful", 16);
						// check it
						client_userID = uid;
						char buf[1024];
						read(client_socket, buf, 96);
						UserIdAndPorts[client_userID] = string(buf);
						portsToUserIDS[string(buf)].insert(client_userID);
					}
					else
					{
						write(client_socket, "You already have an active session", 34);
					}
				}
			}
		}
		else if (command == "logout")
		{
			if (activeUsers[client_userID])
			{
				activeUsers[client_userID] = false;
				string port = UserIdAndPorts[client_userID];
				UserIdAndPorts.erase(client_userID);
				portsToUserIDS.erase(port);
				write(client_socket, "Logged out", 10);
			}
			else
			{
				write(client_socket, "please login before logout", 26);
			}
		}

		else if (command == "create_group")
		{
			if (input_line_vec.size() != 2)
			{
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				string gid = input_line_vec[1];

				if (find(Groups.begin(), Groups.end(), gid) != Groups.end())
				{
					write(client_socket, "Group exists", 12);
				}
				else
				{
					Groups.push_back(gid);
					GroupAdmins.insert({gid, client_userID});
					GroupMembers[gid].insert(client_userID);
					write(client_socket, "Group created", 13);
				}
			}
		}
		else if (command == "list_groups")
		{
			if (input_line_vec.size() != 1)
			{
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				// write(client_socket, "Groups:", 7);
				if (Groups.size() == 0)
				{
					write(client_socket, "No groups", 9);
				}
				else
				{
					string GroupsDetailsStr = "";
					for (string g : Groups)
					{
						GroupsDetailsStr += g + "%";
					}
					write(client_socket, &GroupsDetailsStr[0], GroupsDetailsStr.length());
				}
			}
		}
		else if (command == "join_group")
		{
			if (input_line_vec.size() != 2)
			{
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				string gid = input_line_vec[1];
				if (find(Groups.begin(), Groups.end(), gid) != Groups.end())
				{
					if (GroupMembers[gid].find(client_userID) == GroupMembers[gid].end())
					{
						GroupPendingReqs[gid].insert(client_userID);
						write(client_socket, "Group request sent and waiting for approval", 43);
					}
					else
					{
						write(client_socket, "You are already in this group", 30);
					}
				}
				else
				{
					write(client_socket, "Invalid Group ID", 16);
				}
			}
		}
		else if (command == "list_requests")
		{
			// std::cout << "inside" << endl;
			if (input_line_vec.size() != 2)
			{
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				string gid = input_line_vec[1];
				//	std::cout << "req: " << gid << endl;
				// write(client_socket, "Group join requests:", 20);
				if (find(Groups.begin(), Groups.end(), gid) == Groups.end())
				{
					write(client_socket, "Invalid Group ID", 16);
				}
				else if (GroupAdmins[gid] != client_userID)
				{
					write(client_socket, "You are not admin of this group", 31);
				}
				else if (GroupPendingReqs[gid].size() == 0)
				{
					write(client_socket, "No requests", 11);
				}
				else
				{
					string listGroupsStr = "";
					for (auto gpr = GroupPendingReqs[gid].begin(); gpr != GroupPendingReqs[gid].end(); gpr++)
					{
						listGroupsStr += string(*gpr) + "%";
					}
					write(client_socket, &listGroupsStr[0], listGroupsStr.length());
				}
			}
		}
		else if (command == "accept_request")
		{
			if (input_line_vec.size() != 3)
			{
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				// write(client_socket, "Accepting request....", 21);

				string gid = input_line_vec[1];
				string cid = input_line_vec[2];
				if (find(Groups.begin(), Groups.end(), gid) == Groups.end())
				{
					write(client_socket, "Invalid Group ID", 16);
				}
				else if (GroupPendingReqs[gid].find(cid) == GroupPendingReqs[gid].end())
				{
					write(client_socket, "No request found", 16);
				}
				else
				{
					GroupPendingReqs[gid].erase(cid);
					GroupMembers[gid].insert(cid);
					write(client_socket, "Request Accepted", 16);
				}
			}
		}
		else if (command == "send")
		{
			write(client_socket, "sending", 7);
			string fileName = input_line_vec[1];
			size_t size;
			FILE *fp = fopen(fileName.c_str(), "r");
			if (fp)
			{
				long long FS = file_size(&fileName[0]);
				// std::cout << "file size: " << FS << endl;
				long long left_chunk = FS % CHUNK;
				long long chunks = FS / CHUNK;
				char data[CHUNK] = {0};
				while ((size = fread(data, 1, CHUNK, fp)) > 0)
				{
					// std::cout << strlen(data) << endl;
					send(client_socket, data, size, 0);
					memset(data, 0, sizeof(data));
				}
				if (chunks > 0 && left_chunk > 0)
				{
					size = fread(data, 1, left_chunk, fp);
					send(client_socket, data, size, 0);
				}
			}
			else
			{
				write(client_socket, "Error while reading file", 24);
			}
			//	std::cout << "send" << endl;
			write(client_socket, "done", 4);
			fclose(fp);
		}
		else if (command == "leave_group")
		{
			if (input_line_vec.size() != 2)
			{
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				string gid = input_line_vec[1];
				// write(client_socket, "Leaving group...", 17);

				if (find(Groups.begin(), Groups.end(), gid) == Groups.end())
				{
					write(client_socket, "Invalid Group ID", 16);
				}
				else
				{
					if (GroupMembers[gid].find(client_userID) == GroupMembers[gid].end())
					{
						write(client_socket, "You are not part of this group", 30);
					}
					else
					{
						if (GroupAdmins[gid] == client_userID)
						{
							// std::cout<<"admin leaving"<<endl;
							write(client_socket, "you are admin", 13);
						}
						else
						{
							GroupMembers[gid].erase(client_userID);
							write(client_socket, "left successfully", 17);
						}
					}
				}
			}
		}
		else if (command == "download_file")
		{
			if (input_line_vec.size() != 4)
			{
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				string gid = input_line_vec[1];
				string fileName = input_line_vec[2];
				string path = input_line_vec[3];
				if (find(Groups.begin(), Groups.end(), gid) == Groups.end())
				{
					write(client_socket, "Invalid Group ID", 16);
				}
				else
				{
					if (GroupMembers[gid].find(client_userID) == GroupMembers[gid].end())
					{
						write(client_socket, "You are not part of this group", 30);
					}
					else
					{
						if (!validpath(path))
						{
							write(client_socket, "Invalid dest path", 17);
						}
						else if (GroupToFiles[gid].find(fileName) == GroupToFiles[gid].end())
						{
							write(client_socket, "File not found", 14);
						}
						else
						{
							// get all ports and send to client
							string file_ports = "";
							set<string> usersWithFile = FileDetails[fileName].FGU[gid];
							for (auto port = FileNameToPort[fileName].begin(); port != FileNameToPort[fileName].end(); port++)
							{
								set<string> usersWithPorts = portsToUserIDS[string(*port)];
								for (auto user = usersWithPorts.begin(); user != usersWithPorts.end(); user++)
								{
									
									if (activeUsers[string(*user)] )
									{
										file_ports = file_ports + string(*port) + "%";
									}
								}
							}
							long long FS = FileDetails[fileName].Filesize;
							file_ports = file_ports + to_string(FS) + "%";
							write(client_socket, &file_ports[0], file_ports.length());
							// std::cout<<"port files info sent: "<<file_ports<<endl;
						}
					}
				}
			}
		}
		else if (command == "upload_file")
		{
			// std::cout << "starting of upload_file" << endl;
			if (input_line_vec.size() != 3)
			{
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				string gid = input_line_vec[2];
				string filePath = input_line_vec[1];
				struct stat fileStat;
				if (GroupMembers.find(gid) == GroupMembers.end())
				{
					write(client_socket, "Invalid Group ID", 16);
					// std::cout << "a" << endl;
				}
				else if (GroupMembers[gid].find(client_userID) == GroupMembers[gid].end())
				{
					write(client_socket, "Not a member", 12);
					//	std::cout << "aa" << endl;
				}
				else if (stat(filePath.c_str(), &fileStat) != 0)
				{
					write(client_socket, "Invalid file path", 17);
					//	std::cout << "aaa" << endl;
				}
				else
				{
					write(client_socket, "Started uploading", 17);
					//	std::cout << "else" << endl;
					char uploaded_client_msg[10240] = {0};
					read(client_socket, uploaded_client_msg, 10240);

					vector<string> vec = split(string(uploaded_client_msg), '%');
					string fileName = vec[0];
					//	std::cout << "upload filename: " << fileName << endl;
					// bzero(uploaded_client_msg, 10240);

					// read(client_socket, uploaded_client_msg, 10240);
					string num_chunks = vec[1];
					FileToChunks[fileName] = num_chunks;

					//	bzero(uploaded_client_msg, 10240);

					// read(client_socket, uploaded_client_msg, 10240);
					string file_port = vec[2];
					FileNameToPort[fileName].insert(file_port);

					GroupToFiles[gid].insert(fileName);
					usersToFiles[client_userID].insert(fileName);
					// FileToChunks[fileName] = vec[3];
					NameToPath[fileName] = vec[4];
					//	std::cout << "success upload" << endl;
					FileDetails[fileName].num_chunks = stoll(vec[3]);
					FileDetails[fileName].fileName = fileName;
					FileDetails[fileName].filePath = vec[4];
					FileDetails[fileName].Filesize = stoll(vec[3]);
					FileDetails[fileName].uploaded_users.insert(client_userID);
					FileDetails[fileName].FGU[gid].insert(client_userID);
				}
			}
		}

		else if (command == "list_files")
		{
			if (input_line_vec.size() != 2)
			{
				write(client_socket, "Invalid command", 15);
			}
			else
			{
				string gid = input_line_vec[1];
				if (find(Groups.begin(), Groups.end(), gid) == Groups.end())
				{
					write(client_socket, "Invalid Group ID", 16);
				}
				else
				{
					if (GroupMembers[gid].find(client_userID) == GroupMembers[gid].end())
					{
						write(client_socket, "You are not part of this group", 30);
					}
					else
					{
						if (GroupToFiles[gid].size() == 0)
						{
							write(client_socket, "No Files", 8);
						}
						else
						{
							write(client_socket, "replying", 8);
							string list_files_reply = "";
							// std::cout<<"list_files_reply  "<<list_files_reply<<endl;
							for (auto it = GroupToFiles[gid].begin(); it != GroupToFiles[gid].end(); it++)
							{
								list_files_reply += string(*it) + "%";
							}
							// std::cout<<"list_files_reply  "<<list_files_reply<<endl;
							write(client_socket, list_files_reply.c_str(), list_files_reply.length());
						}
					}
				}
			}
		}
		else if (command == "stop_share")
		{
			string gid = input_line_vec[1];
			string filename = input_line_vec[2];
			set<string> group_mems = GroupMembers[gid];

			if (find(Groups.begin(), Groups.end(), gid) == Groups.end())
			{
				write(client_socket, "Invalid Group ID", 16);
			}
			else
			{
				if (GroupMembers[gid].find(client_userID) == GroupMembers[gid].end())
				{
					write(client_socket, "You are not part of this group", 30);
				}
				else
				{
					if (GroupToFiles[gid].find(filename) == GroupToFiles[gid].end())
					{
						write(client_socket, "File not found in this group", 28);
					}
					else
					{
						FileDetails[filename].FGU[gid].erase(client_userID);

						write(client_socket, "stop_share executed successfully", 32);
					}
				}
			}

			// FileNameToPort
			// portsToUserIDS
			// UserIdAndPorts
		}
		// else if (command == "show_downloads")
		// {
		// }
		else
		{
			// Invalid command
			bzero(input_line,1024);
			write(client_socket, "Invalid command entered", 15);
		}
	}
	
	return NULL;
}

int main(int argc, char *argv[])
{

	if (argc != 3)
	{
		std::cout << "Invalid pattern" << endl;
		return 0;
	}

	// getting tracker file details	start
	fstream trackerInfoFile;
	string trackerFileName = argv[1];
	trackerInfoFile.open(trackerFileName, ios::in);
	vector<string> trackerDetails;
	if (trackerInfoFile.is_open())
	{
		string str;
		while (getline(trackerInfoFile, str))
		{
			trackerDetails.push_back(str);
		}
		trackerInfoFile.close();
	}
	else
	{
		std::cout << "Error while opening tracker info file" << endl;
		exit(0);
	}
	if (string(argv[2]) == "1")
	{
		tracker_ip1 = trackerDetails[0];
		tracker_port1 = stoi(trackerDetails[1]);
		currentTrackerIP = tracker_ip1;
		currentTrackerPORT = tracker_port1;
	}
	else
	{
		tracker_ip2 = trackerDetails[2];
		tracker_port2 = stoi(trackerDetails[3]);
		currentTrackerIP = tracker_ip2;
		currentTrackerPORT = tracker_port2;
	}

	// getting tracker file details end

	int trackerSocket;
	struct sockaddr_in serv_addr;
	int serveraddrSize = sizeof(serv_addr);
	int SetSocketOpt = 1;
	pthread_t quitThread;

	if ((trackerSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("Socket creation failed");
		exit(0);
	}

	if (setsockopt(trackerSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &SetSocketOpt, sizeof(SetSocketOpt)))
	{
		perror("setsockopt");
		exit(0);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(currentTrackerPORT);

	if (inet_pton(AF_INET, &currentTrackerIP[0], &serv_addr.sin_addr) <= 0)
	{
		std::cout << endl
				  << "Invalid addressn" << endl;
		return -1;
	}

	if (bind(trackerSocket, (SA *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("Error in Bind");
		exit(EXIT_FAILURE);
	}

	if (listen(trackerSocket, 10) < 0)
	{
		perror("error in listen");
		exit(0);
	}

	if (pthread_create(&quitThread, NULL, checkQuit, NULL) == -1)
	{
		perror("error in quit thread");
		exit(0);
	}
	std::cout << "[+]Server started" << endl;
	while (1)
	{
		int clientSocket;

		if ((clientSocket = accept(trackerSocket, (struct sockaddr *)&serv_addr, (socklen_t *)&serveraddrSize)) < 0)
		{
			perror("error in accepting");
			exit(0);
		}
		pthread_t handle_thread;
		int *pclient = (int *)malloc(sizeof(int));
		*pclient = clientSocket;
		pthread_create(&handle_thread, NULL, handle_client, pclient);
	}
	return 0;
}
