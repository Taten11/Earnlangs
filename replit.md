# Dream Earning

## Overview

Dream Earning is a task-based rewards platform where users can complete tasks to earn points, which can then be withdrawn as real currency. The application features user authentication, a task completion system, a points-based reward system, and a comprehensive admin panel for site management.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes (January 2026)

- Complete task submission system with screenshot upload
- Users can upload proof screenshots for task completion
- Admin panel for reviewing submissions (approve/reject)
- Points credited automatically on admin approval
- Added History page to view all submission statuses
- Reorganized user dashboard with bottom navigation (Tasks, Withdraw, History, Profile)
- Mobile-friendly responsive design throughout
- Database includes User, Task, Submission, and Payout models

## System Architecture

### Backend Framework
- **Framework**: Flask (Python)
- **Rationale**: Lightweight Python web framework suitable for small to medium applications.

### Database & ORM
- **Database**: PostgreSQL
- **ORM**: Flask-SQLAlchemy
- **Rationale**: SQLAlchemy provides a robust ORM layer for database operations. The application includes a URL scheme fix for Postgres compatibility.

### Data Models
1. **User**: username, password_hash, points, is_admin, is_banned, date_joined, last_login, tasks_completed
2. **Task**: title, description, reward, link, is_active, task_type, created_at
3. **Payout**: user_id, method, account, amount, status, date_requested

### Authentication
- **Library**: Flask-Login
- **Password Security**: Werkzeug's password hashing
- **Features**: Session-based authentication with login_required decorator protection
- **Admin Login**: Username: `admin`, Password: `admin123`

### Frontend Architecture
- **Templating**: Jinja2 (Flask's default)
- **Styling**: Tailwind CSS (via CDN)
- **Icons**: Font Awesome (via CDN)
- **Design Pattern**: Server-side rendered templates with responsive, mobile-first design

### Key Routes Structure

#### User Routes
- `/` - Index/redirect to dashboard
- `/login` - User authentication
- `/signup` - User registration  
- `/dashboard` - Main user interface (Tasks, Withdraw, Profile sections)
- `/payout` - Submit payout request (POST)
- `/logout` - Session termination

#### Admin Routes
- `/admin` - Admin dashboard with statistics
- `/admin/users` - User management table
- `/admin/users/<id>/edit` - Edit user points
- `/admin/users/<id>/ban` - Ban/unban user
- `/admin/users/<id>/delete` - Delete user
- `/admin/tasks` - Task management table
- `/admin/tasks/add` - Add new task
- `/admin/tasks/<id>/edit` - Edit task
- `/admin/tasks/<id>/toggle` - Activate/deactivate task
- `/admin/tasks/<id>/delete` - Delete task
- `/admin/payouts` - Payout management with filters
- `/admin/payouts/<id>/approve` - Approve payout
- `/admin/payouts/<id>/decline` - Decline payout (refunds points)
- `/admin/payouts/<id>/paid` - Mark as paid
- `/admin/payouts/export` - Export payouts to CSV

### Points System
- Users earn points by completing tasks
- Conversion rate: 10 Points = ₱1.00
- Minimum withdrawal: 100 points
- Payout methods: GCash, PayPal
- Payout requests are queued for admin approval

## External Dependencies

### Python Packages
- **Flask**: Web framework
- **Flask-SQLAlchemy**: Database ORM integration
- **Flask-Login**: User session management
- **Werkzeug**: Password hashing utilities
- **psycopg2-binary**: PostgreSQL adapter

### Frontend CDN
- **Tailwind CSS**: Utility-first CSS framework
- **Font Awesome**: Icon library

### Database
- **PostgreSQL**: Primary database (connection via DATABASE_URL environment variable)

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string

## File Structure
```
/
├── main.py                 # Flask application with all routes
├── templates/
│   ├── login.html          # Login page
│   ├── signup.html         # Registration page
│   ├── dashboard.html      # User dashboard with sections
│   └── admin/
│       ├── dashboard.html  # Admin statistics dashboard
│       ├── users.html      # User management
│       ├── edit_user.html  # Edit user form
│       ├── tasks.html      # Task management
│       ├── add_task.html   # Add task form
│       ├── edit_task.html  # Edit task form
│       └── payouts.html    # Payout management
└── replit.md               # Project documentation
```
