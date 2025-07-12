# main.py - Complete Cricket Betting Backend
import os
import sqlite3
import hashlib
import requests
import asyncio
import json
import re
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import uvicorn
from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()

# ============= CONFIGURATION =============
DATABASE_PATH = os.getenv("DATABASE_PATH", "/app/data/cricket_bet.db")
RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# ============= FASTAPI APP =============
app = FastAPI(title="Cricket Betting API", version="1.0.0")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============= PYDANTIC MODELS =============
class UserCreate(BaseModel):
    mobile: str
    password: str

class UserLogin(BaseModel):
    mobile: str
    password: str

class BetCreate(BaseModel):
    match_id: int
    predicted_winner: str
    predicted_player: str
    bet_amount: float

class BalanceRequest(BaseModel):
    amount: float

class WithdrawalRequest(BaseModel):
    amount: float
    upi_id: str

class MatchResult(BaseModel):
    match_id: int
    winner: str
    player_of_match: str

class CallOffMatch(BaseModel):
    match_id: int
    reason: str

# ============= DATABASE FUNCTIONS =============
def init_database():
    """Initialize SQLite database with all tables"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mobile VARCHAR(15) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        balance DECIMAL(10,2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Matches table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_match_id VARCHAR(50) UNIQUE,
        team1 VARCHAR(100),
        team2 VARCHAR(100),
        match_title VARCHAR(200),
        match_date DATETIME,
        venue VARCHAR(200),
        series VARCHAR(200),
        status VARCHAR(20) DEFAULT 'upcoming',
        winner VARCHAR(100),
        player_of_match VARCHAR(100),
        called_off BOOLEAN DEFAULT FALSE,
        called_off_reason TEXT,
        called_off_at TIMESTAMP,
        squad_fetched BOOLEAN DEFAULT FALSE,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Players table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER,
        player_name VARCHAR(100),
        team VARCHAR(100),
        role VARCHAR(50) DEFAULT 'Player',
        FOREIGN KEY (match_id) REFERENCES matches(id)
    )
    ''')
    
    # Bets table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS bets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        match_id INTEGER,
        predicted_winner VARCHAR(100),
        predicted_player VARCHAR(100),
        bet_amount DECIMAL(10,2),
        potential_winnings DECIMAL(10,2),
        status VARCHAR(20) DEFAULT 'pending',
        refunded BOOLEAN DEFAULT FALSE,
        refund_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (match_id) REFERENCES matches(id)
    )
    ''')
    
    # Balance requests table (deposits)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS balance_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount DECIMAL(10,2),
        type VARCHAR(20) DEFAULT 'deposit',
        status VARCHAR(20) DEFAULT 'pending',
        admin_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Withdrawal requests table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount DECIMAL(10,2),
        upi_id VARCHAR(100),
        status VARCHAR(20) DEFAULT 'pending',
        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP,
        admin_notes TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # API usage tracking
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS api_usage_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date DATE,
        calls_used INTEGER,
        calls_limit INTEGER DEFAULT 100,
        endpoint_breakdown TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Platform settings
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS platform_settings (
        setting_key VARCHAR(50) PRIMARY KEY,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Insert default settings
    cursor.execute('''
    INSERT OR IGNORE INTO platform_settings (setting_key, setting_value) VALUES
    ('min_bet_amount', '10'),
    ('max_bet_amount', '1000'),
    ('min_withdrawal_amount', '100'),
    ('betting_closes_hours_before_match', '1'),
    ('welcome_bonus', '100')
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    """Hash password with SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

# ============= CRICKET API FUNCTIONS =============
async def fetch_upcoming_matches():
    """Fetch upcoming matches from RapidAPI"""
    if not RAPIDAPI_KEY:
        print("No RAPIDAPI_KEY configured")
        return []
    
    url = "https://cricket-live-line1.p.rapidapi.com/upcomingMatches"
    headers = {
        "X-RapidAPI-Key": RAPIDAPI_KEY,
        "X-RapidAPI-Host": "cricket-live-line1.p.rapidapi.com"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            matches_data = response.json()
            print(f"API Response: {matches_data}")
            
            # Handle different response formats
            if isinstance(matches_data, dict):
                matches = matches_data.get('data', matches_data.get('matches', [matches_data]))
            else:
                matches = matches_data
            
            return matches if isinstance(matches, list) else []
        else:
            print(f"API Error: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        print(f"Error fetching matches: {e}")
        return []

async def fetch_match_squad(match_id: str):
    """Fetch match squad from RapidAPI"""
    if not RAPIDAPI_KEY:
        return []
    
    url = f"https://cricket-live-line1.p.rapidapi.com/match/{match_id}/squads"
    headers = {
        "X-RapidAPI-Key": RAPIDAPI_KEY,
        "X-RapidAPI-Host": "cricket-live-line1.p.rapidapi.com"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            squad_data = response.json()
            return parse_squad_data(squad_data)
    except Exception as e:
        print(f"Squad fetch attempt failed: {e}")
    
    print(f"Squad fetch failed for match {match_id}")
    return []

def parse_squad_data(squad_data):
    """Parse squad response into standardized format"""
    players = []
    
    # Handle the new API response format
    if isinstance(squad_data, dict) and 'data' in squad_data:
        data = squad_data['data']
        for team_key, team_info in data.items():
            if isinstance(team_info, dict) and 'player' in team_info:
                team_name = team_info.get('name', team_key)
                for player in team_info['player']:
                    players.append({
                        'name': player.get('name', ''),
                        'team': team_name,
                        'role': player.get('play_role', 'Player')
                    })
        return players
    
    # Fallback to old parsing logic if needed
    try:
        # Handle different response formats
        if isinstance(squad_data, dict):
            if 'data' in squad_data:
                data = squad_data['data']
            elif 'squads' in squad_data:
                data = squad_data['squads']
            else:
                data = squad_data
        else:
            data = squad_data
        
        # Extract players from various formats
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    players.extend(extract_players_from_team(item))
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, list):
                    for player in value:
                        if isinstance(player, dict):
                            players.append({
                                'name': player.get('name', player.get('player_name', str(player))),
                                'team': key,
                                'role': player.get('role', 'Player')
                            })
                        elif isinstance(player, str):
                            players.append({
                                'name': player,
                                'team': key,
                                'role': 'Player'
                            })
        
        return players
        
    except Exception as e:
        print(f"Squad parsing error: {e}")
        return []

def extract_players_from_team(team_data):
    """Extract players from team object"""
    players = []
    team_name = team_data.get('team_name', team_data.get('name', 'Unknown'))
    
    player_fields = ['players', 'squad', 'team_players', 'members']
    
    for field in player_fields:
        if field in team_data and isinstance(team_data[field], list):
            for player in team_data[field]:
                if isinstance(player, dict):
                    players.append({
                        'name': player.get('name', player.get('player_name', '')),
                        'team': team_name,
                        'role': player.get('role', player.get('position', 'Player'))
                    })
                elif isinstance(player, str):
                    players.append({
                        'name': player,
                        'team': team_name,
                        'role': 'Player'
                    })
    
    return players

# ============= SIMPLE MATCH SELECTION =============
def smart_match_selection(matches, target_count=20):
    """Select first 20 upcoming matches without any filtering"""
    print(f"📝 Total matches received from API: {len(matches)}")
    
    # Simply take the first 20 matches from the API
    selected_matches = matches[:target_count]
    
    print(f"✅ Selected {len(selected_matches)} matches for platform")
    
    # Show selected matches for debugging
    for i, match in enumerate(selected_matches[:5]):  # Show first 5
        team_a = match.get('team_a', match.get('teamA', 'Team A'))
        team_b = match.get('team_b', match.get('teamB', 'Team B'))
        match_date = match.get('date_wise', match.get('match_date', 'No date'))
        print(f"{i+1}. {team_a} vs {team_b} on {match_date}")
    
    if len(selected_matches) > 5:
        print(f"... and {len(selected_matches) - 5} more matches")
    
    return selected_matches

# ============= AUTHENTICATION FUNCTIONS =============
def authenticate_user(mobile: str, password: str):
    """Simple authentication"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    hashed_password = hash_password(password)
    cursor.execute(
        "SELECT * FROM users WHERE mobile = ? AND password = ?",
        (mobile, hashed_password)
    )
    user = cursor.fetchone()
    conn.close()
    
    return dict(user) if user else None

def get_current_user(request: Request):
    """Get current user from headers"""
    user_id = request.headers.get("X-User-ID")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return dict(user)

def is_valid_upi_id(upi_id: str) -> bool:
    """Basic UPI ID validation"""
    pattern = r'^[a-zA-Z0-9\.\-_]{2,256}@[a-zA-Z]{2,64}$'
    return bool(re.match(pattern, upi_id))

# ============= API ENDPOINTS =============

@app.get("/")
async def root():
    return {"message": "Cricket Betting API", "version": "1.0.0", "status": "active"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "database": "connected",
        "app_ready": True
    }

# ============= USER REGISTRATION & LOGIN =============

@app.post("/register")
async def register(user_data: UserCreate):
    """User registration with welcome bonus"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Validate mobile number
    if not re.match(r'^[6-9]\d{9}$', user_data.mobile):
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid mobile number format")
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE mobile = ?", (user_data.mobile,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Mobile number already registered")
    
    # Create user with welcome bonus
    hashed_password = hash_password(user_data.password)
    welcome_bonus = 100.0  # Welcome bonus
    
    cursor.execute(
        "INSERT INTO users (mobile, password, balance) VALUES (?, ?, ?)",
        (user_data.mobile, hashed_password, welcome_bonus)
    )
    
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {
        "message": "Registration successful", 
        "user_id": user_id, 
        "welcome_bonus": welcome_bonus,
        "mobile": user_data.mobile
    }

@app.post("/login")
async def login(login_data: UserLogin):
    """User login"""
    user = authenticate_user(login_data.mobile, login_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid mobile number or password")
    
    return {
        "message": "Login successful", 
        "user": {
            "id": user["id"],
            "mobile": user["mobile"],
            "balance": user["balance"]
        }
    }

# ============= MATCHES =============

@app.get("/matches")
async def get_matches():
    """Get upcoming matches for betting"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT * FROM matches 
    WHERE status = 'upcoming' 
    AND called_off = FALSE 
    AND squad_fetched = TRUE
    ORDER BY created_at DESC
    LIMIT 20
""")
    matches = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {"matches": matches}

@app.get("/matches/{match_id}/players")
async def get_match_players(match_id: int):
    """Get players for a specific match"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get match details
    cursor.execute("SELECT * FROM matches WHERE id = ?", (match_id,))
    match = cursor.fetchone()
    
    if not match:
        raise HTTPException(status_code=404, detail="Match not found")
    
    # Get players
    cursor.execute("SELECT * FROM players WHERE match_id = ?", (match_id,))
    players = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "match": dict(match),
        "players": players
    }

# ============= BETTING =============

@app.post("/place-bet")
async def place_bet(bet_data: BetCreate, current_user: dict = Depends(get_current_user)):
    """Place bet with validation"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Validate bet amount
    if bet_data.bet_amount < 10:
        raise HTTPException(400, "Minimum bet amount is ₹10")
    
    if bet_data.bet_amount > 1000:
        raise HTTPException(400, "Maximum bet amount is ₹1000")
    
    # 2. Check user balance
    if current_user['balance'] < bet_data.bet_amount:
        raise HTTPException(400, "Insufficient balance")
    
    # 3. Check if user already bet on this match
    cursor.execute("""
        SELECT COUNT(*) as count FROM bets 
        WHERE user_id = ? AND match_id = ? AND status = 'pending'
    """, (current_user['id'], bet_data.match_id))
    
    if cursor.fetchone()['count'] > 0:
        conn.close()
        raise HTTPException(400, "You have already placed a bet on this match")
    
    # 4. Check if match exists and is bettable
    cursor.execute("""
        SELECT * FROM matches 
        WHERE id = ? AND status = 'upcoming' AND called_off = FALSE
    """, (bet_data.match_id,))
    
    match = cursor.fetchone()
    if not match:
        conn.close()
        raise HTTPException(400, "Match not available for betting")
    
        # 5. Check betting cutoff time
    try:
        # Parse "12 Jul 2025, Saturday" format  
        match_date_str = match['match_date'].split(',')[0].strip()  # "12 Jul 2025"
        match_date = datetime.strptime(match_date_str, '%d %b %Y')
        betting_cutoff = match_date - timedelta(hours=1)
    except:
        # Fallback - allow betting if date parsing fails
        match_date = datetime.now() + timedelta(days=1)
        betting_cutoff = match_date - timedelta(hours=1)

    # if datetime.now() >= betting_cutoff:
    #     conn.close()
    #     raise HTTPException(400, "Betting closed - match starts soon")
    
    # 6. Validate team selection
    if bet_data.predicted_winner not in [match['team1'], match['team2']]:
        conn.close()
        raise HTTPException(400, "Invalid team selection")
    
    # 7. Validate player selection
    cursor.execute("""
        SELECT COUNT(*) as count FROM players 
        WHERE match_id = ? AND player_name = ?
    """, (bet_data.match_id, bet_data.predicted_player))
    
    if cursor.fetchone()['count'] == 0:
        conn.close()
        raise HTTPException(400, "Selected player not found in match squad")
    
    # 8. Place bet
    new_balance = current_user['balance'] - bet_data.bet_amount
    
    # Update user balance
    cursor.execute(
        "UPDATE users SET balance = ? WHERE id = ?", 
        (new_balance, current_user['id'])
    )
    
    # Create bet
    cursor.execute("""
        INSERT INTO bets (
            user_id, match_id, predicted_winner, predicted_player, 
            bet_amount, potential_winnings, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', datetime('now'))
    """, (
        current_user['id'], bet_data.match_id, bet_data.predicted_winner,
        bet_data.predicted_player, bet_data.bet_amount, bet_data.bet_amount * 3
    ))
    
    bet_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {
        "message": "Bet placed successfully",
        "bet_id": bet_id,
        "new_balance": new_balance,
        "potential_winnings": bet_data.bet_amount * 3
    }

@app.get("/my-bets")
async def get_my_bets(current_user: dict = Depends(get_current_user)):
    """Get user's betting history"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            b.*,
            m.match_title,
            m.team1,
            m.team2,
            m.match_date,
            m.venue,
            m.status as match_status,
            m.called_off,
            m.winner,
            m.player_of_match
        FROM bets b
        JOIN matches m ON b.match_id = m.id
        WHERE b.user_id = ?
        ORDER BY b.created_at DESC
    """, (current_user['id'],))
    
    bets = [dict(row) for row in cursor.fetchall()]
    
    # Add result analysis
    for bet in bets:
        if bet['called_off']:
            bet['result_analysis'] = "Match cancelled - Bet refunded"
        elif bet['status'] == 'won':
            bet['result_analysis'] = f"Won! Earned ₹{bet['potential_winnings']}"
        elif bet['status'] == 'lost':
            bet['result_analysis'] = "Lost. Better luck next time!"
        elif bet['status'] == 'pending':
            bet['result_analysis'] = "Match pending. Results will be updated soon."
        elif bet['status'] == 'refunded':
            bet['result_analysis'] = f"Refunded: {bet['refund_reason']}"
    
    conn.close()
    return {"bets": bets}

# ============= BALANCE MANAGEMENT =============

@app.post("/request-deposit")
async def request_deposit(deposit_data: BalanceRequest, current_user: dict = Depends(get_current_user)):
    """Request balance addition"""
    if deposit_data.amount < 10:
        raise HTTPException(400, "Minimum deposit amount is ₹10")
    
    if deposit_data.amount > 10000:
        raise HTTPException(400, "Maximum deposit amount is ₹10,000")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO balance_requests (user_id, amount, type, status)
        VALUES (?, ?, 'deposit', 'pending')
    """, (current_user['id'], deposit_data.amount))
    
    request_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {
        "message": "Deposit request submitted successfully",
        "request_id": request_id,
        "amount": deposit_data.amount,
        "note": "Please pay the amount and admin will approve your request"
    }

@app.post("/request-withdrawal")
async def request_withdrawal(withdrawal_data: WithdrawalRequest, current_user: dict = Depends(get_current_user)):
    """Request withdrawal"""
    # Validate amount
    if withdrawal_data.amount < 100:
        raise HTTPException(400, "Minimum withdrawal amount is ₹100")
    
    if withdrawal_data.amount > current_user['balance']:
        raise HTTPException(400, "Insufficient balance")
    
    # Validate UPI ID
    if not is_valid_upi_id(withdrawal_data.upi_id):
        raise HTTPException(400, "Invalid UPI ID format")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Deduct amount from balance immediately
    new_balance = current_user['balance'] - withdrawal_data.amount
    cursor.execute(
        "UPDATE users SET balance = ? WHERE id = ?", 
        (new_balance, current_user['id'])
    )
    
    # Create withdrawal request
    cursor.execute("""
        INSERT INTO withdrawal_requests 
        (user_id, amount, upi_id, status, requested_at)
        VALUES (?, ?, ?, 'pending', datetime('now'))
    """, (current_user['id'], withdrawal_data.amount, withdrawal_data.upi_id))
    
    request_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {
        "message": "Withdrawal request submitted successfully",
        "request_id": request_id,
        "new_balance": new_balance,
        "note": "Amount deducted from wallet. Admin will process within 24 hours."
    }

@app.get("/my-withdrawals")
async def get_my_withdrawals(current_user: dict = Depends(get_current_user)):
    """Get withdrawal history"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM withdrawal_requests 
        WHERE user_id = ? 
        ORDER BY requested_at DESC
    """, (current_user['id'],))
    
    withdrawals = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {"withdrawals": withdrawals}

# ============= USER PROFILE =============

@app.get("/profile")
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    """Get user profile with stats"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get betting statistics
    cursor.execute("""
        SELECT 
            COUNT(*) as total_bets,
            COUNT(CASE WHEN status = 'won' THEN 1 END) as won_bets,
            COUNT(CASE WHEN status = 'lost' THEN 1 END) as lost_bets,
            COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_bets,
            COUNT(CASE WHEN status = 'refunded' THEN 1 END) as refunded_bets,
            COALESCE(SUM(bet_amount), 0) as total_staked,
            COALESCE(SUM(CASE WHEN status = 'won' THEN potential_winnings ELSE 0 END), 0) as total_winnings
        FROM bets 
        WHERE user_id = ?
    """, (current_user['id'],))
    
    stats = dict(cursor.fetchone())
    
    # Calculate win rate
    if stats['total_bets'] > 0:
        stats['win_rate'] = round((stats['won_bets'] / stats['total_bets']) * 100, 2)
    else:
        stats['win_rate'] = 0
    
    conn.close()
    
    return {
        "user": current_user,
        "betting_stats": stats
    }

# Add test endpoint for debugging API response
@app.get("/admin/debug-api")
async def debug_cricket_api(admin_password: str):
    """Debug cricket API response format"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    try:
        matches = await fetch_upcoming_matches()
        return {
            "total_matches": len(matches),
            "sample_matches": matches[:3] if matches else [],
            "first_match_keys": list(matches[0].keys()) if matches else [],
            "api_working": True
        }
    except Exception as e:
        return {"error": str(e), "api_working": False}

# Add manual trigger for testing
@app.post("/admin/manual-update")
async def manual_cricket_update(admin_password: str):
    """Manually trigger cricket data update for testing"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    try:
        await daily_cricket_update()
        return {"message": "Cricket data update completed successfully"}
    except Exception as e:
        return {"message": f"Update failed: {str(e)}"}

# ============= ADMIN ENDPOINTS =============

@app.get("/admin/dashboard")
async def admin_dashboard(admin_password: str):
    """Admin dashboard with stats"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get platform stats
    cursor.execute("SELECT COUNT(*) as total_users FROM users")
    total_users = cursor.fetchone()['total_users']
    
    cursor.execute("SELECT COUNT(*) as pending_deposits FROM balance_requests WHERE status = 'pending'")
    pending_deposits = cursor.fetchone()['pending_deposits']
    
    cursor.execute("SELECT COUNT(*) as pending_withdrawals FROM withdrawal_requests WHERE status = 'pending'")
    pending_withdrawals = cursor.fetchone()['pending_withdrawals']
    
    cursor.execute("SELECT COUNT(*) as active_bets FROM bets WHERE status = 'pending'")
    active_bets = cursor.fetchone()['active_bets']
    
    cursor.execute("SELECT COUNT(*) as total_matches FROM matches WHERE called_off = FALSE")
    total_matches = cursor.fetchone()['total_matches']
    
    cursor.execute("SELECT COALESCE(SUM(balance), 0) as total_user_balance FROM users")
    total_user_balance = cursor.fetchone()['total_user_balance']
    
    conn.close()
    
    return {
        "total_users": total_users,
        "pending_deposits": pending_deposits,
        "pending_withdrawals": pending_withdrawals,
        "active_bets": active_bets,
        "total_matches": total_matches,
        "total_user_balance": total_user_balance
    }

# Add this endpoint for testing - put it near other admin endpoints
@app.post("/admin/manual-update")
async def manual_cricket_update(admin_password: str):
    """Manually trigger cricket data update for testing"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    try:
        await daily_cricket_update()
        return {"message": "Cricket data update completed successfully"}
    except Exception as e:
        return {"message": f"Update failed: {str(e)}"}

@app.get("/admin/deposit-requests")
async def get_deposit_requests(admin_password: str):
    """Get pending deposit requests"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT br.*, u.mobile, u.balance as current_balance
        FROM balance_requests br
        JOIN users u ON br.user_id = u.id
        WHERE br.status = 'pending' AND br.type = 'deposit'
        ORDER BY br.created_at ASC
    """)
    
    requests = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {"deposit_requests": requests}

@app.post("/admin/approve-deposit")
async def approve_deposit_request(
    request_id: int, 
    action: str,  # 'approve' or 'reject'
    admin_notes: str = "",
    admin_password: str = None
):
    """Admin approves or rejects deposit request"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    if action not in ['approve', 'reject']:
        raise HTTPException(400, "Action must be 'approve' or 'reject'")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get request details
    cursor.execute("""
        SELECT * FROM balance_requests WHERE id = ? AND status = 'pending'
    """, (request_id,))
    
    request_data = cursor.fetchone()
    if not request_data:
        conn.close()
        raise HTTPException(404, "Deposit request not found or already processed")
    
    if action == 'approve':
        # Add money to user balance
        cursor.execute("""
            UPDATE users SET balance = balance + ? WHERE id = ?
        """, (request_data['amount'], request_data['user_id']))
        
        # Mark as approved
        cursor.execute("""
            UPDATE balance_requests 
            SET status = 'approved', processed_at = datetime('now'), admin_notes = ?
            WHERE id = ?
        """, (admin_notes or "Deposit approved successfully", request_id))
        
        message = f"Deposit request approved for ₹{request_data['amount']}"
        
    else:  # reject
        # Mark as rejected
        cursor.execute("""
            UPDATE balance_requests 
            SET status = 'rejected', processed_at = datetime('now'), admin_notes = ?
            WHERE id = ?
        """, (admin_notes or "Deposit request rejected", request_id))
        
        message = f"Deposit request rejected"
    
    conn.commit()
    conn.close()
    
    return {"message": message}

@app.get("/admin/withdrawal-requests")
async def get_withdrawal_requests(admin_password: str):
    """Get pending withdrawal requests"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT wr.*, u.mobile, u.balance as current_balance
        FROM withdrawal_requests wr
        JOIN users u ON wr.user_id = u.id
        WHERE wr.status = 'pending'
        ORDER BY wr.requested_at ASC
    """)
    
    requests = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {"withdrawal_requests": requests}

@app.post("/admin/process-withdrawal")
async def process_withdrawal_request(
    request_id: int, 
    action: str,  # 'approve' or 'reject'
    admin_notes: str = "",
    admin_password: str = None
):
    """Admin approves or rejects withdrawal request"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    if action not in ['approve', 'reject']:
        raise HTTPException(400, "Action must be 'approve' or 'reject'")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get withdrawal request details
    cursor.execute("""
        SELECT * FROM withdrawal_requests WHERE id = ? AND status = 'pending'
    """, (request_id,))
    
    request_data = cursor.fetchone()
    if not request_data:
        conn.close()
        raise HTTPException(404, "Withdrawal request not found or already processed")
    
    if action == 'approve':
        # Mark as completed (admin manually sent money)
        cursor.execute("""
            UPDATE withdrawal_requests 
            SET status = 'completed', processed_at = datetime('now'), admin_notes = ?
            WHERE id = ?
        """, (admin_notes or "Withdrawal processed successfully", request_id))
        
        message = f"Withdrawal request approved for ₹{request_data['amount']}"
        
    else:  # reject
        # Return money to user balance
        cursor.execute("""
            UPDATE users SET balance = balance + ? WHERE id = ?
        """, (request_data['amount'], request_data['user_id']))
        
        # Mark as rejected
        cursor.execute("""
            UPDATE withdrawal_requests 
            SET status = 'rejected', processed_at = datetime('now'), admin_notes = ?
            WHERE id = ?
        """, (admin_notes or "Withdrawal request rejected", request_id))
        
        message = f"Withdrawal request rejected. ₹{request_data['amount']} returned to user wallet"
    
    conn.commit()
    conn.close()
    
    return {"message": message}

@app.get("/admin/matches")
async def get_admin_matches(admin_password: str):
    """Get all matches for admin management"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            m.*,
            COUNT(b.id) as total_bets,
            COALESCE(SUM(b.bet_amount), 0) as total_bet_amount,
            COALESCE(SUM(CASE WHEN b.status = 'pending' THEN b.potential_winnings ELSE 0 END), 0) as potential_payout
        FROM matches m
        LEFT JOIN bets b ON m.id = b.match_id
        WHERE m.called_off = FALSE
        GROUP BY m.id
        ORDER BY m.match_date ASC
    """)
    
    matches = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {"matches": matches}

@app.get("/admin/match-bets/{match_id}")
async def get_match_bets(match_id: int, admin_password: str):
    """View all bets for a specific match"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get match details
    cursor.execute("SELECT * FROM matches WHERE id = ?", (match_id,))
    match = cursor.fetchone()
    
    if not match:
        raise HTTPException(404, "Match not found")
    
    # Get all bets for this match
    cursor.execute("""
        SELECT b.*, u.mobile
        FROM bets b
        JOIN users u ON b.user_id = u.id
        WHERE b.match_id = ?
        ORDER BY b.created_at DESC
    """, (match_id,))
    
    bets = [dict(row) for row in cursor.fetchall()]
    
    # Calculate totals
    total_bets = len(bets)
    total_amount = sum(bet['bet_amount'] for bet in bets)
    potential_payout = sum(bet['potential_winnings'] for bet in bets if bet['status'] == 'pending')
    
    conn.close()
    
    return {
        "match": dict(match),
        "bets": bets,
        "stats": {
            "total_bets": total_bets,
            "total_amount": total_amount,
            "potential_payout": potential_payout
        }
    }

@app.post("/admin/update-match-result")
async def update_match_result(result_data: MatchResult, admin_password: str):
    """Update match result and settle bets"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Validate match exists
    cursor.execute("SELECT * FROM matches WHERE id = ?", (result_data.match_id,))
    match = cursor.fetchone()
    
    if not match:
        raise HTTPException(404, "Match not found")
    
    if match['called_off']:
        raise HTTPException(400, "Cannot update result for called off match")
    
    # Update match result
    cursor.execute("""
        UPDATE matches 
        SET winner = ?, player_of_match = ?, status = 'completed', last_updated = datetime('now')
        WHERE id = ?
    """, (result_data.winner, result_data.player_of_match, result_data.match_id))
    
    # Get all pending bets for this match
    cursor.execute("""
        SELECT * FROM bets 
        WHERE match_id = ? AND status = 'pending'
    """, (result_data.match_id,))
    
    pending_bets = cursor.fetchall()
    
    winners_count = 0
    total_winnings = 0
    
    # Settle bets
    for bet in pending_bets:
        # Check if both predictions are correct (winner + player of match)
        if (bet['predicted_winner'] == result_data.winner and 
            bet['predicted_player'] == result_data.player_of_match):
            
            # Winner - add winnings to balance
            cursor.execute("""
                UPDATE users SET balance = balance + ? WHERE id = ?
            """, (bet['potential_winnings'], bet['user_id']))
            
            cursor.execute("""
                UPDATE bets SET status = 'won' WHERE id = ?
            """, (bet['id'],))
            
            winners_count += 1
            total_winnings += bet['potential_winnings']
        else:
            # Lost bet
            cursor.execute("""
                UPDATE bets SET status = 'lost' WHERE id = ?
            """, (bet['id'],))
    
    conn.commit()
    conn.close()
    
    return {
        "message": "Match result updated and bets settled successfully",
        "match_title": match['match_title'],
        "winner": result_data.winner,
        "player_of_match": result_data.player_of_match,
        "total_bets": len(pending_bets),
        "winners": winners_count,
        "total_winnings_paid": total_winnings
    }

@app.post("/admin/call-off-match")
async def call_off_match(call_off_data: CallOffMatch, admin_password: str):
    """Call off a match and refund all bets"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if match exists
    cursor.execute("SELECT * FROM matches WHERE id = ?", (call_off_data.match_id,))
    match = cursor.fetchone()
    
    if not match:
        conn.close()
        raise HTTPException(404, "Match not found")
    
    if match['called_off']:
        conn.close()
        raise HTTPException(400, "Match already called off")
    
    # Get all pending bets for this match
    cursor.execute("""
        SELECT user_id, bet_amount FROM bets 
        WHERE match_id = ? AND status = 'pending'
    """, (call_off_data.match_id,))
    
    pending_bets = cursor.fetchall()
    total_refunded = 0
    users_affected = len(pending_bets)
    
    # Refund all bets
    for bet in pending_bets:
        # Return money to user balance
        cursor.execute("""
            UPDATE users SET balance = balance + ? WHERE id = ?
        """, (bet['bet_amount'], bet['user_id']))
        
        total_refunded += bet['bet_amount']
    
    # Mark all bets as refunded
    cursor.execute("""
        UPDATE bets 
        SET status = 'refunded', refunded = TRUE, refund_reason = ?
        WHERE match_id = ? AND status = 'pending'
    """, (call_off_data.reason, call_off_data.match_id))
    
    # Mark match as called off
    cursor.execute("""
        UPDATE matches 
        SET called_off = TRUE, called_off_reason = ?, called_off_at = datetime('now'), status = 'cancelled'
        WHERE id = ?
    """, (call_off_data.reason, call_off_data.match_id))
    
    conn.commit()
    conn.close()
    
    return {
        "message": "Match called off successfully",
        "match_title": match['match_title'],
        "reason": call_off_data.reason,
        "users_affected": users_affected,
        "total_refunded": total_refunded
    }

# Add this test endpoint for debugging API response
@app.get("/admin/debug-api")
async def debug_cricket_api(admin_password: str):
    """Debug cricket API response format"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    try:
        matches = await fetch_upcoming_matches()
        return {
            "total_matches": len(matches),
            "sample_matches": matches[:3] if matches else [],
            "first_match_keys": list(matches[0].keys()) if matches else [],
            "api_working": True
        }
    except Exception as e:
        return {"error": str(e), "api_working": False}

# Add manual trigger for testing
@app.post("/admin/manual-update")
async def manual_cricket_update(admin_password: str):
    """Manually trigger cricket data update for testing"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid admin password")
    
    try:
        await daily_cricket_update()
        return {"message": "Cricket data update completed successfully"}
    except Exception as e:
        return {"message": f"Update failed: {str(e)}"}

# ============= CRON JOB / SCHEDULER =============

async def daily_cricket_update():
    """Daily job to fetch matches and update data"""
    print("🏏 Starting daily cricket update...")
    
    daily_call_count = 0
    max_daily_calls = 85
    
    try:
        # 1. Fetch upcoming matches
        print("📡 Fetching upcoming matches...")
        upcoming_matches = await fetch_upcoming_matches()
        daily_call_count += 1
        
        if not upcoming_matches:
            print("❌ No matches fetched from API")
            return
        
        print(f"✅ Found {len(upcoming_matches)} total matches")
        
        # 2. Select first 20 matches (no filtering)
        selected_matches = smart_match_selection(upcoming_matches, target_count=20)
        print(f"🎯 Selected {len(selected_matches)} matches for platform")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 3. Process each selected match
        for match in selected_matches:
            if daily_call_count >= max_daily_calls:
                break
            
            try:
                # Extract match data with flexible field mapping
                api_match_id = str(match.get('match_id', match.get('id', match.get('matchId', ''))))
                team1 = match.get('team_a', match.get('teamA', match.get('team1', '')))
                team2 = match.get('team_b', match.get('teamB', match.get('team2', '')))
                match_title = match.get('title', match.get('name', f"{team1} vs {team2}"))
                match_date = match.get('date_wise', match.get('match_date', match.get('date', '')))
                venue = match.get('venue', match.get('location', ''))
                series = match.get('series', match.get('tournament', match.get('competition', '')))
                
                if not all([api_match_id, team1, team2, match_date]):
                    continue
                
                # Check if match already exists
                cursor.execute("""
                    SELECT id, squad_fetched FROM matches 
                    WHERE api_match_id = ?
                """, (api_match_id,))
                
                existing_match = cursor.fetchone()
                
                if existing_match and existing_match['squad_fetched']:
                    print(f"⏭️  Squad already exists for: {match_title}")
                    continue
                
                # Insert or update match
                if not existing_match:
                    cursor.execute("""
                        INSERT INTO matches 
                        (api_match_id, team1, team2, match_title, match_date, venue, series)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (api_match_id, team1, team2, match_title, match_date, venue, series))
                    match_db_id = cursor.lastrowid
                    print(f"➕ New match added: {match_title}")
                else:
                    match_db_id = existing_match['id']
                
                # Fetch squad
                print(f"👥 Fetching squad for: {match_title}")
                squad = await fetch_match_squad(api_match_id)
                daily_call_count += 1
                
                if squad:
                    # Delete existing players and add new ones
                    cursor.execute("DELETE FROM players WHERE match_id = ?", (match_db_id,))
                    
                    for player in squad:
                        cursor.execute("""
                            INSERT INTO players (match_id, player_name, team, role)
                            VALUES (?, ?, ?, ?)
                        """, (match_db_id, player['name'], player['team'], player['role']))
                    
                    # Mark squad as fetched
                    cursor.execute("""
                        UPDATE matches SET squad_fetched = TRUE, last_updated = datetime('now') 
                        WHERE id = ?
                    """, (match_db_id,))
                    
                    print(f"✅ Squad updated: {len(squad)} players")
                else:
                    print(f"❌ No squad data received")
                
                # Rate limiting
                await asyncio.sleep(2)
                
            except Exception as e:
                print(f"❌ Error processing match {match.get('name', 'Unknown')}: {e}")
                continue
        
        # 4. Log API usage
        cursor.execute("""
            INSERT INTO api_usage_log (date, calls_used, calls_limit)
            VALUES (DATE('now'), ?, 100)
        """, (daily_call_count,))
        
        conn.commit()
        conn.close()
        
        print(f"🎯 Daily update completed! API calls used: {daily_call_count}/100")
        
    except Exception as e:
        print(f"❌ Daily update failed: {e}")

def log_daily_usage(calls_used):
    """Log daily API usage"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT OR REPLACE INTO api_usage_log 
        (date, calls_used, calls_limit)
        VALUES (DATE('now'), ?, 100)
    """, (calls_used,))
    
    conn.commit()
    conn.close()

# ============= APP STARTUP =============

@app.on_event("startup")
async def startup_event():
    """Initialize app on startup"""
    print("🚀 Starting Cricket Betting API...")
    
    # Initialize database
    print("📊 Initializing database...")
    init_database()
    
    # Setup scheduler for daily updates
    scheduler = AsyncIOScheduler()
    
    # Run daily at 6 AM IST
    scheduler.add_job(
        daily_cricket_update, 
        'cron', 
        hour=6, 
        minute=0,
        timezone='Asia/Kolkata'
    )
    
    scheduler.start()
    
    print("✅ Cricket Betting API started successfully!")
    print("📅 Daily cricket data update scheduled for 6:00 AM IST")

# ============= MAIN =============

if __name__ == "__main__":
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=int(os.getenv("PORT", 8000)),
        log_level="info"
    )