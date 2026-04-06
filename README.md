# Authentication Service

This is the Authentication microservice for the Mikoshi project. It is built with Flask and provides authentication and authorization features.

## Prerequisites

- Python 3.11 or newer
- pip (Python package manager)
- (Optional) Docker

## Setup & Installation

1. **Clone the repository and navigate to this folder:**
   ```bash
   cd Authentication
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   Create a `.env` file in this directory with the following variables:
   ```env
   SUPABASE_URL=your_supabase_url
   SUPABASE_KEY=your_supabase_key
   PORT=6601
   USER=your_user
   ORIGIN=http://localhost:6620
   ```

4. **Run the Flask app:**
   ```bash
   python app.py
   ```
   The service will start on the port specified in your `.env` (default: 6601).

   ```

## API Documentation

- Swagger UI is available at `/apidocs` when the service is running.
- Health check endpoint: `GET /health`

## Troubleshooting

- Ensure all environment variables are set correctly in your `.env` file.
- If you change dependencies, rebuild your Docker image.
- For CORS issues, check the `ORIGIN` variable in your `.env`.

---
For more details, see the code and comments in `app.py` or contact the project maintainers.
