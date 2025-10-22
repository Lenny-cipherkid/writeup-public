#!/bin/bash

# BookWorm HTB Machine Installation Script
# OS: Ubuntu Server 22.04 LTS
# Machine Type: Easy
# Author: HTB Machine Creator

set -e

echo "=================================================="
echo "BookWorm HTB Machine Installation Script"
echo "=================================================="
echo "This script will configure Ubuntu Server 22.04 LTS"
echo "for the BookWorm HTB machine."
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_status "Starting BookWorm machine setup..."

# 1. System Updates and Basic Configuration
print_status "Updating system packages..."
apt update && apt upgrade -y

# Set hostname
print_status "Setting hostname to bookworm..."
hostnamectl set-hostname bookworm
echo "127.0.1.1 bookworm.htb bookworm" >> /etc/hosts

# Set timezone and locale
print_status "Configuring timezone and locale..."
timedatectl set-timezone UTC
locale-gen en_US.UTF-8
update-locale LANG=en_US.UTF-8

# 2. Install required packages
print_status "Installing required packages..."
apt install -y apache2 php8.1 php8.1-sqlite3 sqlite3 openssh-server sudo curl wget unzip cron

# 3. Configure networking (remove netplan, use interfaces)
print_status "Configuring network interfaces..."
apt purge -y netplan.io nplan
rm -rf /etc/netplan/*

cat > /etc/network/interfaces << 'EOF'
# interfaces(5) file used by ifup(8) and ifdown(8)
auto lo
iface lo inet loopback

auto ens33
iface ens33 inet dhcp
EOF

# 4. Create users with proper passwords
print_status "Creating users..."

# Create bookworm user
useradd -m -s /bin/bash bookworm
echo "bookworm:MyBooksAreMyTreasure2024" | chpasswd
usermod -aG sudo bookworm

# Set root password
echo "root:LibraryMasterKey2024!" | chpasswd

# 5. Configure SSH
print_status "Configuring SSH..."
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart ssh

# 6. Configure Apache and PHP
print_status "Configuring Apache and PHP..."
systemctl enable apache2
systemctl start apache2

# Enable PHP module
a2enmod php8.1

# Create web directory structure
mkdir -p /var/www/html/{uploads,css,js}
chown -R www-data:www-data /var/www/html
chmod 755 /var/www/html/uploads

# 7. Create the web application files
print_status "Creating web application..."

# Main index.php
cat > /var/www/html/index.php << 'EOF'
<?php
$db = new SQLite3('/var/www/library.db');

// Create table if not exists
$db->exec('CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    description TEXT,
    cover_image TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)');

// Insert sample books if table is empty
$result = $db->query('SELECT COUNT(*) as count FROM books');
$row = $result->fetchArray();
if ($row['count'] == 0) {
    $sample_books = [
        ['The Great Gatsby', 'F. Scott Fitzgerald', 'A classic American novel about the Jazz Age'],
        ['To Kill a Mockingbird', 'Harper Lee', 'A gripping tale of racial injustice and childhood'],
        ['1984', 'George Orwell', 'A dystopian social science fiction novel'],
        ['Pride and Prejudice', 'Jane Austen', 'A romantic novel of manners'],
        ['The Catcher in the Rye', 'J.D. Salinger', 'A controversial coming-of-age story']
    ];
    
    foreach ($sample_books as $book) {
        $stmt = $db->prepare('INSERT INTO books (title, author, description) VALUES (?, ?, ?)');
        $stmt->bindParam(1, $book[0]);
        $stmt->bindParam(2, $book[1]);
        $stmt->bindParam(3, $book[2]);
        $stmt->execute();
    }
}

$search = $_GET['search'] ?? '';
if ($search) {
    $stmt = $db->prepare('SELECT * FROM books WHERE title LIKE ? OR author LIKE ? ORDER BY created_at DESC');
    $searchTerm = "%$search%";
    $stmt->bindParam(1, $searchTerm);
    $stmt->bindParam(2, $searchTerm);
    $result = $stmt->execute();
} else {
    $result = $db->query('SELECT * FROM books ORDER BY created_at DESC');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BookWorm Library - Online Book Catalog</title>
    <link href="css/style.css" rel="stylesheet">
</head>
<body>
    <header>
        <h1>📚 BookWorm Library</h1>
        <p>Welcome to our online book catalog</p>
    </header>
    
    <nav>
        <a href="index.php">Home</a>
        <a href="admin.php">Admin Panel</a>
    </nav>
    
    <main>
        <div class="search-box">
            <form method="GET">
                <input type="text" name="search" placeholder="Search books or authors..." value="<?php echo htmlspecialchars($search); ?>">
                <button type="submit">Search</button>
            </form>
        </div>
        
        <div class="books-grid">
            <?php while ($book = $result->fetchArray(SQLITE3_ASSOC)): ?>
            <div class="book-card">
                <div class="book-cover">
                    <?php if ($book['cover_image']): ?>
                        <img src="uploads/<?php echo htmlspecialchars($book['cover_image']); ?>" alt="Book cover">
                    <?php else: ?>
                        <div class="no-cover">📖</div>
                    <?php endif; ?>
                </div>
                <div class="book-info">
                    <h3><?php echo htmlspecialchars($book['title']); ?></h3>
                    <p class="author">by <?php echo htmlspecialchars($book['author']); ?></p>
                    <p class="description"><?php echo htmlspecialchars($book['description']); ?></p>
                </div>
            </div>
            <?php endwhile; ?>
        </div>
    </main>
    
    <footer>
        <p>&copy; 2024 BookWorm Library. Managed with love by our dedicated librarian.</p>
    </footer>
</body>
</html>
EOF

# Admin panel with vulnerable file upload
cat > /var/www/html/admin.php << 'EOF'
<?php
$message = '';

if ($_POST) {
    $title = $_POST['title'] ?? '';
    $author = $_POST['author'] ?? '';
    $description = $_POST['description'] ?? '';
    
    $cover_image = '';
    if (isset($_FILES['cover']) && $_FILES['cover']['error'] === UPLOAD_ERR_OK) {
        $upload_dir = 'uploads/';
        $original_name = $_FILES['cover']['name'];
        
        // VULNERABLE: Only basic client-side validation, server accepts any file
        $cover_image = time() . '_' . $original_name;
        $upload_path = $upload_dir . $cover_image;
        
        if (move_uploaded_file($_FILES['cover']['tmp_name'], $upload_path)) {
            chmod($upload_path, 0644);
        } else {
            $cover_image = '';
        }
    }
    
    if ($title && $author) {
        $db = new SQLite3('/var/www/library.db');
        $stmt = $db->prepare('INSERT INTO books (title, author, description, cover_image) VALUES (?, ?, ?, ?)');
        $stmt->bindParam(1, $title);
        $stmt->bindParam(2, $author);
        $stmt->bindParam(3, $description);
        $stmt->bindParam(4, $cover_image);
        
        if ($stmt->execute()) {
            $message = '<div class="success">Book added successfully!</div>';
        } else {
            $message = '<div class="error">Failed to add book.</div>';
        }
    } else {
        $message = '<div class="error">Title and author are required.</div>';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - BookWorm Library</title>
    <link href="css/style.css" rel="stylesheet">
</head>
<body>
    <header>
        <h1>📚 Admin Panel</h1>
        <p>Add new books to the library</p>
    </header>
    
    <nav>
        <a href="index.php">Back to Catalog</a>
    </nav>
    
    <main>
        <?php echo $message; ?>
        
        <form method="POST" enctype="multipart/form-data" class="admin-form">
            <div class="form-group">
                <label for="title">Book Title *</label>
                <input type="text" id="title" name="title" required>
            </div>
            
            <div class="form-group">
                <label for="author">Author *</label>
                <input type="text" id="author" name="author" required>
            </div>
            
            <div class="form-group">
                <label for="description">Description</label>
                <textarea id="description" name="description" rows="4"></textarea>
            </div>
            
            <div class="form-group">
                <label for="cover">Book Cover Image</label>
                <input type="file" id="cover" name="cover" accept="image/*" onchange="validateFile()">
                <small>Accepted formats: JPG, JPEG, PNG, GIF</small>
            </div>
            
            <button type="submit">Add Book</button>
        </form>
    </main>
    
    <script>
        // CLIENT-SIDE ONLY validation (vulnerable!)
        function validateFile() {
            var fileInput = document.getElementById('cover');
            var file = fileInput.files[0];
            
            if (file) {
                var allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
                var fileName = file.name.toLowerCase();
                var fileExtension = fileName.split('.').pop();
                
                if (!allowedExtensions.includes(fileExtension)) {
                    alert('Please select a valid image file (JPG, JPEG, PNG, GIF)');
                    fileInput.value = '';
                }
            }
        }
    </script>
</body>
</html>
EOF

# CSS file
cat > /var/www/html/css/style.css << 'EOF'
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Georgia', serif;
    line-height: 1.6;
    color: #333;
    background-color: #f4f4f4;
}

header {
    background: linear-gradient(135deg, #8B4513, #D2691E);
    color: white;
    text-align: center;
    padding: 2rem;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

header h1 {
    font-size: 2.5rem;
    margin-bottom: 0.5rem;
}

nav {
    background: #654321;
    padding: 1rem;
    text-align: center;
}

nav a {
    color: white;
    text-decoration: none;
    margin: 0 1rem;
    padding: 0.5rem 1rem;
    border-radius: 5px;
    transition: background 0.3s;
}

nav a:hover {
    background: rgba(255,255,255,0.2);
}

main {
    max-width: 1200px;
    margin: 2rem auto;
    padding: 0 2rem;
}

.search-box {
    text-align: center;
    margin-bottom: 2rem;
}

.search-box input {
    padding: 0.8rem;
    font-size: 1rem;
    border: 2px solid #ddd;
    border-radius: 25px;
    width: 300px;
    margin-right: 0.5rem;
}

.search-box button {
    padding: 0.8rem 1.5rem;
    font-size: 1rem;
    background: #8B4513;
    color: white;
    border: none;
    border-radius: 25px;
    cursor: pointer;
}

.books-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 2rem;
    margin: 2rem 0;
}

.book-card {
    background: white;
    border-radius: 10px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    overflow: hidden;
    transition: transform 0.3s;
}

.book-card:hover {
    transform: translateY(-5px);
}

.book-cover {
    height: 200px;
    background: #f8f8f8;
    display: flex;
    align-items: center;
    justify-content: center;
}

.book-cover img {
    max-width: 100%;
    max-height: 100%;
    object-fit: cover;
}

.no-cover {
    font-size: 4rem;
    color: #ccc;
}

.book-info {
    padding: 1.5rem;
}

.book-info h3 {
    color: #8B4513;
    margin-bottom: 0.5rem;
}

.author {
    font-style: italic;
    color: #666;
    margin-bottom: 0.5rem;
}

.description {
    color: #555;
    font-size: 0.9rem;
}

.admin-form {
    max-width: 600px;
    margin: 0 auto;
    background: white;
    padding: 2rem;
    border-radius: 10px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

.form-group {
    margin-bottom: 1.5rem;
}

.form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: bold;
    color: #8B4513;
}

.form-group input,
.form-group textarea {
    width: 100%;
    padding: 0.8rem;
    border: 2px solid #ddd;
    border-radius: 5px;
    font-size: 1rem;
}

.form-group small {
    color: #666;
    font-size: 0.8rem;
}

.admin-form button {
    width: 100%;
    padding: 1rem;
    font-size: 1.1rem;
    background: #8B4513;
    color: white;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background 0.3s;
}

.admin-form button:hover {
    background: #654321;
}

.success {
    background: #d4edda;
    color: #155724;
    padding: 1rem;
    border-radius: 5px;
    margin-bottom: 1rem;
    border: 1px solid #c3e6cb;
}

.error {
    background: #f8d7da;
    color: #721c24;
    padding: 1rem;
    border-radius: 5px;
    margin-bottom: 1rem;
    border: 1px solid #f5c6cb;
}

footer {
    text-align: center;
    padding: 2rem;
    background: #333;
    color: white;
    margin-top: 3rem;
}
EOF

# 8. Set up database with proper permissions
print_status "Setting up SQLite database..."
touch /var/www/library.db
chown www-data:www-data /var/www/library.db
chmod 664 /var/www/library.db

# 9. Configure sudo permissions for privilege escalation
print_status "Configuring sudo permissions..."

# Create a simple Python script for bookworm user
cat > /var/www/add_book.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import sys

def add_book(title, author, description=""):
    conn = sqlite3.connect('/var/www/library.db')
    cursor = conn.cursor()
    
    cursor.execute('INSERT INTO books (title, author, description) VALUES (?, ?, ?)',
                   (title, author, description))
    conn.commit()
    conn.close()
    print(f"Book '{title}' by {author} added successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 add_book.py <title> <author> [description]")
        sys.exit(1)
    
    title = sys.argv[1]
    author = sys.argv[2]
    description = sys.argv[3] if len(sys.argv) > 3 else ""
    
    add_book(title, author, description)
EOF

chmod +x /var/www/add_book.py
chown bookworm:bookworm /var/www/add_book.py

# Configure sudo permissions
cat > /etc/sudoers.d/bookworm << 'EOF'
# Allow www-data to run the add_book script as bookworm
www-data ALL=(bookworm) NOPASSWD: /usr/bin/python3 /var/www/add_book.py

# Allow bookworm to run pip3 as root (VULNERABLE for privilege escalation)
bookworm ALL=(root) NOPASSWD: /usr/bin/pip3
EOF

# 10. Set up cron jobs for cleanup and maintenance
print_status "Setting up cron jobs..."

# Cleanup uploaded files
cat > /etc/cron.d/bookworm-cleanup << 'EOF'
# Clean old uploaded files every 10 minutes
*/10 * * * * www-data find /var/www/html/uploads -type f -mmin +60 -delete 2>/dev/null

# Daily database backup
0 2 * * * bookworm cp /var/www/library.db /home/bookworm/library_backup.db 2>/dev/null
EOF

# 11. Create and place flags
print_status "Creating flags..."

# Generate MD5 flags
USER_FLAG=$(echo -n "BookWorm_User_$(date +%s)" | md5sum | cut -d' ' -f1)
ROOT_FLAG=$(echo -n "BookWorm_Root_$(date +%s)" | md5sum | cut -d' ' -f1)

# Place user flag
echo "$USER_FLAG" > /home/bookworm/user.txt
chown root:bookworm /home/bookworm/user.txt
chmod 644 /home/bookworm/user.txt

# Place root flag
echo "$ROOT_FLAG" > /root/root.txt
chown root:root /root/root.txt
chmod 640 /root/root.txt

# 12. Secure history files
print_status "Securing history files..."

# Redirect history to /dev/null for all users
echo 'export HISTFILE=/dev/null' >> /etc/profile
echo 'export HISTFILE=/dev/null' >> /home/bookworm/.bashrc
echo 'export HISTFILE=/dev/null' >> /root/.bashrc

# Remove existing history
rm -f /home/bookworm/.bash_history
rm -f /root/.bash_history
rm -f /home/bookworm/.mysql_history
rm -f /root/.mysql_history
rm -f /home/bookworm/.viminfo
rm -f /root/.viminfo

# Create immutable empty history files
touch /home/bookworm/.bash_history /root/.bash_history
chattr +i /home/bookworm/.bash_history /root/.bash_history 2>/dev/null || true

# 13. Final security hardening
print_status "Applying security hardening..."

# Disable unnecessary services
systemctl disable bluetooth 2>/dev/null || true
systemctl disable cups 2>/dev/null || true

# Set proper permissions
find /var/www/html -type f -exec chmod 644 {} \;
find /var/www/html -type d -exec chmod 755 {} \;
chmod 755 /var/www/html/uploads

# Restart services
systemctl restart apache2
systemctl restart cron

# 14. Create machine info file
print_status "Creating machine information..."

cat > /root/machine_info.txt << EOF
================================================
BookWorm HTB Machine Information
================================================

Machine Type: Easy
OS: Ubuntu Server 22.04 LTS
Hostname: bookworm.htb

CREDENTIALS:
- User: bookworm | Password: MyBooksAreMyTreasure2024
- Root: root | Password: LibraryMasterKey2024!

FLAGS:
- User Flag: $USER_FLAG (located in /home/bookworm/user.txt)
- Root Flag: $ROOT_FLAG (located in /root/root.txt)

SERVICES:
- HTTP (Port 80): Apache2 with PHP Library Management App
- SSH (Port 22): Standard OpenSSH

EXPLOITATION PATH:
1. Web Enumeration → Find admin.php
2. File Upload Vulnerability → Upload PHP webshell
3. Lateral Movement → sudo python3 script as bookworm
4. Privilege Escalation → sudo pip3 as root

INTENDED VULNERABILITIES:
- Unrestricted file upload in /admin.php
- Sudo misconfiguration for pip3

Created: $(date)
================================================
EOF

print_success "BookWorm HTB machine setup completed successfully!"
print_warning "Important Information:"
echo -e "  ${YELLOW}User Flag:${NC} $USER_FLAG"
echo -e "  ${YELLOW}Root Flag:${NC} $ROOT_FLAG"
echo ""
print_warning "Next Steps:"
echo "1. Shutdown the VM: sudo shutdown -h now"
echo "2. Take a VM snapshot"
echo "3. Configure VM settings: 2GB RAM, 2 CPU cores"
echo "4. Test the exploitation path"
echo "5. Create documentation package for HTB submission"
echo ""
print_success "Machine is ready for testing and HTB submission!"
