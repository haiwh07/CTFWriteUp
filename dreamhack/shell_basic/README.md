# CHALLENGE: Shell Basic

## Vấn đề
- Chỉ cần viết shellcode đọc flag ở /home/shell_basic/flag_name_is_loooooong là xong.

## Giải pháp
- Sau khi dùng seccomp kiểm tra xem những lệnh nào có thể thực hiện thì thấy không thể sử dụng execve và execveat, nhưng còn lại có thể dùng được.
- Do đó, tôi viết shellcode đẩy đường dẫn vào và dùng read, open, write để lấy flag.
