// Navbar component for application navigation
import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import './Navbar.css';

const Navbar: React.FC = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await logout();
      navigate('/login');
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  return (
    <nav style={navStyle}>
      <div style={navContainerStyle}>
        <Link to="/" style={logoStyle} className="bank-logo">
          <span style={logoIconStyle}>🏦</span>
          <span style={logoTextStyle}>Robin Bank</span>
        </Link>
        
        <div style={navLinksStyle}>
          {isAuthenticated ? (
            <>
              <span style={userInfoStyle}>
                Welcome, {user?.firstName}
              </span>
              <Link to="/dashboard" style={linkStyle}>
                Dashboard
              </Link>
              <Link to="/transactions" style={linkStyle}>
                Transactions
              </Link>
              <div style={dividerStyle}></div>
              <button onClick={handleLogout} style={buttonStyle} className="logout-btn">
                Logout
              </button>
            </>
          ) : (
            <>
              <Link to="/login" style={linkStyle} className="nav-link">
                Login
              </Link>
              <Link to="/register" style={{...buttonStyle, textDecoration: 'none'}} className="register-btn">
                Register
              </Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
};

// Enhanced styles for a more beautiful design
const navStyle: React.CSSProperties = {
  backgroundColor: '#043a6b', // Darker blue for professional banking look
  color: 'white',
  padding: '1rem 0',
  boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
  borderBottom: '3px solid #4caf50',
};

const navContainerStyle: React.CSSProperties = {
  maxWidth: '1200px',
  margin: '0 auto',
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  padding: '0 1.5rem',
};

const logoStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  textDecoration: 'none',
  gap: '0.5rem',
};

const logoIconStyle: React.CSSProperties = {
  fontSize: '1.75rem',
};

const logoTextStyle: React.CSSProperties = {
  fontSize: '1.5rem',
  fontWeight: 'bold',
  color: '#ffffff',
  letterSpacing: '0.5px',
};

const navLinksStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: '1.5rem',
};

const linkStyle: React.CSSProperties = {
  color: '#e0e7ff',
  textDecoration: 'none',
  padding: '0.5rem 0',
  fontWeight: '500',
  position: 'relative',
  transition: 'all 0.2s ease',
};

const buttonStyle: React.CSSProperties = {
  backgroundColor: '#4caf50', // Green for positive action
  color: 'white',
  border: 'none',
  padding: '0.6rem 1.2rem',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: '600',
  fontSize: '0.95rem',
  transition: 'all 0.3s ease',
  boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
};

const userInfoStyle: React.CSSProperties = {
  color: '#a3c2e3',
  fontSize: '0.95rem',
  fontWeight: '500',
};

const dividerStyle: React.CSSProperties = {
  height: '24px',
  width: '1px',
  backgroundColor: 'rgba(255,255,255,0.3)',
};

export default Navbar;