import React from 'react';
import { useAuth } from '../contexts/AuthContext';
import './Dashboard.css';

const Dashboard: React.FC = () => {
  const { user } = useAuth();

  return (
    <div style={containerStyle}>
      <div style={dashboardHeaderStyle}>
        <h1 style={titleStyle}>Welcome to Robin Bank</h1>
        <p style={subtitleStyle}>Hello, {user?.firstName} {user?.lastName}! Here's your financial summary</p>
      </div>

      <div style={summaryContainerStyle}>
        <div style={balanceCardStyle}>
          <div style={balanceHeaderStyle}>
            <h2 style={balanceTitleStyle}>Current Balance</h2>
            <div style={balanceBadgeStyle}>Checking Account</div>
          </div>
          <p style={balanceAmountStyle}>
            ${user?.balance?.toFixed(2) || '0.00'}
          </p>
          <div style={balanceActionsStyle}>
            <button style={primaryButtonStyle} className="dashboard-btn">
              <i className="fas fa-exchange-alt" style={{marginRight: '8px'}}></i>
              Transfer Money
            </button>
            <button style={{...secondaryButtonStyle, marginLeft: '10px'}} className="dashboard-btn">
              <i className="fas fa-history" style={{marginRight: '8px'}}></i>
              Transactions
            </button>
          </div>
        </div>
      </div>

      <div style={cardGridStyle}>
        <div style={cardStyle} className="dashboard-card">
          <div style={cardIconContainerStyle} className="card-icon">
            <i className="fas fa-user-circle" style={cardIconStyle}></i>
          </div>
          <h3 style={cardTitleStyle}>Account Details</h3>
          <div style={cardContentStyle}>
            <div style={detailRowStyle}>
              <span style={detailLabelStyle}>Username</span>
              <span style={detailValueStyle}>{user?.username}</span>
            </div>
            <div style={detailRowStyle}>
              <span style={detailLabelStyle}>Email</span>
              <span style={detailValueStyle}>{user?.email}</span>
            </div>
            <div style={detailRowStyle}>
              <span style={detailLabelStyle}>Account #</span>
              <span style={detailValueStyle}>{user?.accountNumber || 'Not assigned'}</span>
            </div>
            <div style={detailRowStyle}>
              <span style={detailLabelStyle}>Role</span>
              <span style={detailValueStyle}>{user?.role || 'Standard'}</span>
            </div>
          </div>
        </div>

        <div style={cardStyle} className="dashboard-card">
          <div style={cardIconContainerStyle} className="card-icon">
            <i className="fas fa-shield-alt" style={cardIconStyle}></i>
          </div>
          <h3 style={cardTitleStyle}>Security Center</h3>
          <div style={cardContentStyle}>
            <div style={securityItemStyle}>
              <i className="fas fa-check-circle" style={securityCheckStyle}></i>
              <span style={securityTextStyle}>Two-factor authentication</span>
            </div>
            <div style={securityItemStyle}>
              <i className="fas fa-check-circle" style={securityCheckStyle}></i>
              <span style={securityTextStyle}>Email notifications enabled</span>
            </div>
            <div style={securityItemStyle}>
              <i className="fas fa-exclamation-triangle security-alert" style={{...securityCheckStyle, color: '#f39c12'}}></i>
              <span style={securityTextStyle}>Password last updated 3 months ago</span>
            </div>
            <button style={{...actionButtonStyle, marginTop: '15px'}} className="dashboard-action-btn">
              Security Settings
            </button>
          </div>
        </div>

        <div style={cardStyle} className="dashboard-card">
          <div style={cardIconContainerStyle} className="card-icon">
            <i className="fas fa-bolt" style={cardIconStyle}></i>
          </div>
          <h3 style={cardTitleStyle}>Quick Actions</h3>
          <div style={actionButtonsStyle}>
            <button style={actionButtonStyle} className="dashboard-action-btn">
              <i className="fas fa-credit-card" style={{marginRight: '8px'}}></i>
              Manage Cards
            </button>
            <button style={actionButtonStyle} className="dashboard-action-btn">
              <i className="fas fa-money-check" style={{marginRight: '8px'}}></i>
              Pay Bills
            </button>
            <button style={actionButtonStyle} className="dashboard-action-btn">
              <i className="fas fa-cog" style={{marginRight: '8px'}}></i>
              Account Settings
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Inline styles for Robin Bank Dashboard
const containerStyle: React.CSSProperties = {
  maxWidth: '1200px',
  margin: '0 auto',
  padding: '2rem',
  fontFamily: "'Poppins', sans-serif",
};

const dashboardHeaderStyle: React.CSSProperties = {
  marginBottom: '2rem',
  textAlign: 'center',
};

const titleStyle: React.CSSProperties = {
  fontSize: '2.5rem',
  fontWeight: 700,
  color: '#043a6b',
  marginBottom: '0.5rem',
};

const subtitleStyle: React.CSSProperties = {
  fontSize: '1.1rem',
  color: '#666',
  marginBottom: '2rem',
};

const summaryContainerStyle: React.CSSProperties = {
  marginBottom: '2.5rem',
};

const balanceCardStyle: React.CSSProperties = {
  backgroundColor: '#043a6b',
  color: 'white',
  padding: '2rem',
  borderRadius: '12px',
  boxShadow: '0 10px 20px rgba(4, 58, 107, 0.2)',
  position: 'relative',
  overflow: 'hidden',
};

const balanceHeaderStyle: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  marginBottom: '1rem',
};

const balanceTitleStyle: React.CSSProperties = {
  margin: 0,
  fontSize: '1.25rem',
  fontWeight: 500,
};

const balanceBadgeStyle: React.CSSProperties = {
  backgroundColor: 'rgba(255, 255, 255, 0.2)',
  padding: '0.25rem 0.75rem',
  borderRadius: '50px',
  fontSize: '0.875rem',
};

const balanceAmountStyle: React.CSSProperties = {
  fontSize: '3rem',
  fontWeight: 'bold',
  margin: '1.5rem 0',
  color: 'white',
};

const balanceActionsStyle: React.CSSProperties = {
  display: 'flex',
  marginTop: '1.5rem',
};

const primaryButtonStyle: React.CSSProperties = {
  backgroundColor: '#4caf50',
  color: 'white',
  border: 'none',
  padding: '0.75rem 1.25rem',
  borderRadius: '8px',
  fontSize: '0.9rem',
  fontWeight: 600,
  cursor: 'pointer',
  display: 'flex',
  alignItems: 'center',
  transition: 'all 0.3s ease',
  boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
};

const secondaryButtonStyle: React.CSSProperties = {
  backgroundColor: 'rgba(255, 255, 255, 0.2)',
  color: 'white',
  border: 'none',
  padding: '0.75rem 1.25rem',
  borderRadius: '8px',
  fontSize: '0.9rem',
  fontWeight: 600,
  cursor: 'pointer',
  display: 'flex',
  alignItems: 'center',
  transition: 'all 0.3s ease',
};

const cardGridStyle: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
  gap: '1.5rem',
  marginTop: '1rem',
};

const cardStyle: React.CSSProperties = {
  backgroundColor: 'white',
  padding: '1.5rem',
  borderRadius: '12px',
  boxShadow: '0 4px 10px rgba(0,0,0,0.05)',
  border: '1px solid #eef2f7',
  transition: 'transform 0.3s ease, box-shadow 0.3s ease',
  position: 'relative',
};

const cardIconContainerStyle: React.CSSProperties = {
  backgroundColor: 'rgba(4, 58, 107, 0.1)',
  width: '50px',
  height: '50px',
  borderRadius: '50%',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  marginBottom: '1.25rem',
};

const cardIconStyle: React.CSSProperties = {
  fontSize: '1.5rem',
  color: '#043a6b',
};

const cardTitleStyle: React.CSSProperties = {
  fontSize: '1.25rem',
  fontWeight: 600,
  color: '#043a6b',
  marginBottom: '1.25rem',
};

const cardContentStyle: React.CSSProperties = {
  marginTop: '1rem',
};

const detailRowStyle: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  padding: '0.5rem 0',
  borderBottom: '1px solid #eef2f7',
};

const detailLabelStyle: React.CSSProperties = {
  color: '#666',
  fontSize: '0.9rem',
};

const detailValueStyle: React.CSSProperties = {
  color: '#333',
  fontWeight: 500,
  fontSize: '0.9rem',
};

const securityItemStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  marginBottom: '12px',
};

const securityCheckStyle: React.CSSProperties = {
  color: '#4caf50',
  fontSize: '1rem',
  marginRight: '10px',
};

const securityTextStyle: React.CSSProperties = {
  fontSize: '0.9rem',
  color: '#333',
};

const actionButtonsStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: '0.75rem',
};

const actionButtonStyle: React.CSSProperties = {
  backgroundColor: '#043a6b',
  color: 'white',
  border: 'none',
  padding: '0.75rem 1rem',
  borderRadius: '8px',
  fontSize: '0.9rem',
  fontWeight: 500,
  cursor: 'pointer',
  transition: 'all 0.3s ease',
  display: 'flex',
  alignItems: 'center',
};

export default Dashboard;
