### Tracker

1. Run Tracker:

```
g++ -pthread -o tracker tracker.cpp
./tracker​ <TRACKER INFO FILE> <TRACKER NUMBER>
ex: ./tracker tracker_info.txt 1
```

`<TRACKER INFO FILE>` contains the IP, Port details of all the trackers.

```
Ex:
127.0.0.1
5000
127.0.0.1
6000
```

2. Close Tracker:

```
quit
```

### Client:

1. Run Client:

```
g++ -pthread -o client client.cpp
./client​ <IP>:<PORT> <TRACKER INFO FILE>
ex: ./client 127.0.0.1:8000 tracker_info.txt
```

2. Create user account:

```
create_user​ <user_id> <password>
```

3. Login:

```
login​ <user_id> <password>
```

4. Create Group:

```
create_group​ <group_id>
```

5. Join Group:

```
join_group​ <group_id>
```

6. Leave Group:

```
leave_group​ <group_id>
```

7. List pending requests:

```
list_requests ​<group_id>
```

8. Accept Group Joining Request:

```
accept_request​ <group_id> <user_id>
```

9. List All Group In Network:

```
list_groups
```

10. List All sharable Files In Group:

```
list_files​ <group_id>
```

11. Upload File:

```
​upload_file​ <file_path> <group_id​>
```

12. Download File:​

```
download_file​ <group_id> <file_name> <destination_path>
```

13. Logout:​

```
logout
```

14. Show_downloads: ​

```
show_downloads
```

15. Stop sharing: ​

```
stop_share ​<group_id> <file_name>
```
