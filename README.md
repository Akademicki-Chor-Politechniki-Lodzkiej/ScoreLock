# ScoreLock 🎵

A secure Flask-based web application for managing and sharing sheet music PDFs with one-time password authentication.

## Features

✨ **One-Time Password (OTP) Access** - Share secure, single-use codes for library access
🔐 **Admin Panel** - Full control over scores and OTP management  
📚 **Beautiful Library UI** - Clean, responsive interface for browsing scores
📁 **PDF Management** - Upload, view, and delete PDF sheet music
👥 **Multiple Admins** - Support for multiple administrator accounts

## Screenshots

- **Login Page**: Dual authentication with OTP or admin login
- **Library**: Grid view of all available scores with metadata
- **Admin Dashboard**: Manage OTPs, upload scores, and view statistics

## Prerequisites

- Python 3.8 or higher
- MySQL or MariaDB database server
- Modern web browser

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ScoreLock.git
cd ScoreLock
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Create MySQL Database

Open MySQL/MariaDB command line or phpMyAdmin and create a database:

```sql
CREATE DATABASE scorelock CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Optionally, create a dedicated user:

```sql
CREATE USER 'scorelock_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON scorelock.* TO 'scorelock_user'@'localhost';
FLUSH PRIVILEGES;
```

### 4. Configure Environment Variables

Copy the example environment file and edit it:

```bash
copy .env.example .env
```

Edit `.env` file with your settings:

```env
SECRET_KEY=your-very-secret-key-here-change-this-to-random-string
DATABASE_URL=mysql+pymysql://username:password@localhost/scorelock
UPLOAD_FOLDER=scores
```

**Important**: Generate a secure SECRET_KEY. You can use Python:

```python
python -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Initialize the Database

Run the initialization script to create tables and your first admin user:

```bash
python init_db.py
```

Follow the prompts to create your admin account.

### 6. Run the Application

```bash
python main.py
```

The application will be available at `http://localhost:5000`

## Usage

### For Administrators

1. **Login**: Go to `http://localhost:5000` and use the "Admin Login" tab
2. **Generate OTP**: In the admin dashboard, click "Generate New OTP"
3. **Share OTP**: Copy the generated code and share it with users
4. **Upload Scores**: Use the upload form to add new PDF scores
5. **Manage**: View all scores and deactivate OTPs as needed

### For Users

1. **Access**: Visit the application URL
2. **Enter OTP**: Use the provided one-time password
3. **Browse**: View all available scores in the library
4. **View PDFs**: Click on any score to open the PDF

## Database Schema

### Tables

**admins**
- `id` - Primary key
- `username` - Unique username
- `password_hash` - Hashed password
- `created_at` - Account creation timestamp

**otps**
- `id` - Primary key
- `code` - Unique OTP code
- `is_active` - Active status
- `created_at` - Creation timestamp
- `used_at` - Usage timestamp
- `created_by` - Foreign key to admins

**scores**
- `id` - Primary key
- `title` - Score title
- `composer` - Composer name
- `filename` - Stored filename
- `uploaded_at` - Upload timestamp
- `uploaded_by` - Foreign key to admins

## Creating Additional Admin Users

To create more admin accounts:

```bash
python init_db.py create-admin
```

## Security Considerations

- Always use HTTPS in production (configure with a reverse proxy like nginx)
- Keep your SECRET_KEY secure and never commit it to version control
- Use strong passwords for admin accounts
- Regularly review and deactivate unused OTPs
- Consider setting up database backups
- Limit file upload sizes (default: 50MB)

## Production Deployment

For production deployment, use a WSGI server like Gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 main:app
```

Use nginx or Apache as a reverse proxy and enable HTTPS with Let's Encrypt.

## Troubleshooting

### Database Connection Error
- Verify MySQL/MariaDB is running
- Check credentials in `.env` file
- Ensure database exists

### Import Errors
- Run `pip install -r requirements.txt`
- Check Python version (3.8+)

### File Upload Issues
- Check `scores/` folder exists and is writable
- Verify file size limits in `main.py`

## File Structure

```
ScoreLock/
├── main.py              # Main application file
├── models.py            # Database models
├── init_db.py          # Database initialization script
├── requirements.txt     # Python dependencies
├── .env.example        # Environment variables template
├── .gitignore          # Git ignore file
├── templates/          # HTML templates
│   ├── base.html       # Base template
│   ├── login.html      # Login page
│   ├── library.html    # Library view
│   └── admin.html      # Admin dashboard
├── static/             # Static files
│   └── style.css       # Custom styles
└── scores/             # Uploaded PDF files (created automatically)
```

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please open an issue on GitHub.

