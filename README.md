# BGMI Key Store

A Flask-based web application for managing and selling BGMI (Battlegrounds Mobile India) keys. This application allows users to purchase keys and administrators to manage inventory and process payments.

## Features

- User authentication (login/register)
- Admin dashboard for key management
- Bulk key upload functionality
- Payment processing with UTR verification
- QR code payment integration
- User purchase history tracking
- Admin approval system for purchases

## Tech Stack

- Python 3.x
- Flask
- SQLAlchemy
- Bootstrap 5
- SQLite Database

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/bgmi-key-store.git
cd bgmi-key-store
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python app.py
```

5. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Default Admin Credentials

- Username: admin
- Password: admin123

**Important**: Change the admin password after first login!

## Project Structure

```
bgmi-key-store/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── static/            # Static files (CSS, JS, images)
├── templates/         # HTML templates
└── instance/         # Database and instance-specific files
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 