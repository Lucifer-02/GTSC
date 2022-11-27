# Nhiệm vụ
`Viết chương trình nhằm mục đích duyệt file và lưu đường dẫn các file duyệt được`
### Yêu cầu
+ 1 file input nhập đường dẫn thư mục duyệt file
+ 1 file output nhập đường dẫn thư mục lưu kết quả
+ Phải duyệt file trong thư mục và tất cả thư mục con của nó, độ sâu 10
+ Chương trình đang chạy rồi, nếu chạy lại chương trình lần nữa thì không chạy mà đưa ra một thông báo lỗi

# Mô tả hoạt động
>**_Note_**: Chỉ chạy trên Windows 

1. Đầu tiên cần check xem chương trình tên `scan` đã chạy chưa bằng hàm proc_find(), hàm này nhận đối số là tên process rồi tìm process tương ứng trong danh sách các process đang chạy và trả về số process có tên này.
2. Đọc line by line là các path được lưu trong file input làm đối số cho hàm scan() để duyệt file, hàm này dùng biến cục bộ count để kiểm soát số lần đệ quy(độ sâu của subdir).
