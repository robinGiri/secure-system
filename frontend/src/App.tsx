import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.min.css';
import '@fortawesome/fontawesome-free/css/all.min.css';
import './App.css';

import { AuthProvider, useAuth } from './contexts/AuthContext';
import Navbar from './components/Layout/Navbar';
import Footer from './components/Layout/Footer';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import ApiTest from './pages/ApiTest';
import Transactions from './pages/Transactions';

// Protected Route Component
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <div>
          <div className="loading-spinner"></div>
          <p style={{ marginTop: '15px', color: '#043a6b', fontWeight: 500 }}>Loading...</p>
        </div>
      </div>
    );
  }

  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
};

// Public Route Component (redirect to dashboard if already authenticated)
const PublicRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <div>
          <div className="loading-spinner"></div>
          <p style={{ marginTop: '15px', color: '#043a6b', fontWeight: 500 }}>Loading...</p>
        </div>
      </div>
    );
  }

  return !isAuthenticated ? <>{children}</> : <Navigate to="/dashboard" replace />;
};

// Home Component Styles
const homeContainerStyle: React.CSSProperties = {
  width: '100%',
  fontFamily: "'Poppins', sans-serif",
};

const heroSectionStyle: React.CSSProperties = {
  height: '500px',
  background: 'linear-gradient(135deg, #043a6b 0%, #1a6baa 100%)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  color: 'white',
  textAlign: 'center',
  padding: '0 20px',
  position: 'relative',
  overflow: 'hidden',
};

const heroContentStyle: React.CSSProperties = {
  zIndex: 1,
  maxWidth: '800px',
  marginTop: '-50px',
};

const heroTitleStyle: React.CSSProperties = {
  fontSize: '3.5rem',
  fontWeight: 'bold',
  margin: '0 0 15px 0',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  color: '#ffffff',
};

const bankIconStyle: React.CSSProperties = {
  fontSize: '3.5rem',
  marginRight: '15px',
};

const heroSubtitleStyle: React.CSSProperties = {
  fontSize: '1.5rem',
  fontWeight: 300,
  margin: '0 0 30px 0',
  color: '#e0e7ff',
};

const heroButtonsStyle: React.CSSProperties = {
  display: 'flex',
  gap: '20px',
  justifyContent: 'center',
  marginTop: '30px',
};

const primaryButtonStyle: React.CSSProperties = {
  backgroundColor: '#4caf50',
  color: 'white',
  padding: '12px 28px',
  borderRadius: '50px',
  textDecoration: 'none',
  fontWeight: 'bold',
  boxShadow: '0 4px 8px rgba(0,0,0,0.1)',
  transition: 'all 0.3s ease',
  border: 'none',
  fontSize: '1rem',
  display: 'inline-flex',
  alignItems: 'center',
};

const secondaryButtonStyle: React.CSSProperties = {
  backgroundColor: 'transparent',
  color: 'white',
  padding: '12px 28px',
  borderRadius: '50px',
  textDecoration: 'none',
  fontWeight: 'bold',
  boxShadow: 'none',
  transition: 'all 0.3s ease',
  border: '2px solid white',
  fontSize: '1rem',
  display: 'inline-flex',
  alignItems: 'center',
};

const featuresContainerStyle: React.CSSProperties = {
  padding: '80px 20px',
  maxWidth: '1200px',
  margin: '0 auto',
};

const sectionTitleContainerStyle: React.CSSProperties = {
  textAlign: 'center',
  marginBottom: '60px',
};

const sectionTitleStyle: React.CSSProperties = {
  fontSize: '2.5rem',
  fontWeight: 'bold',
  color: '#043a6b',
  margin: '0 0 15px 0',
};

const titleUnderlineStyle: React.CSSProperties = {
  height: '4px',
  width: '80px',
  backgroundColor: '#4caf50',
  margin: '0 auto',
};

const featureCardsContainerStyle: React.CSSProperties = {
  display: 'flex',
  flexWrap: 'wrap',
  justifyContent: 'center',
  gap: '30px',
};

const featureCardStyle: React.CSSProperties = {
  flex: '1 1 300px',
  maxWidth: '350px',
  backgroundColor: 'white',
  borderRadius: '10px',
  padding: '30px',
  textAlign: 'center',
  boxShadow: '0 10px 30px rgba(0,0,0,0.08)',
  transition: 'transform 0.3s ease',
};

const featureIconContainerStyle: React.CSSProperties = {
  backgroundColor: 'rgba(4, 58, 107, 0.1)',
  height: '80px',
  width: '80px',
  borderRadius: '50%',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  margin: '0 auto 25px auto',
};

const featureIconStyle: React.CSSProperties = {
  fontSize: '2rem',
  color: '#043a6b',
};

const featureCardTitleStyle: React.CSSProperties = {
  fontSize: '1.5rem',
  fontWeight: 'bold',
  color: '#043a6b',
  margin: '0 0 15px 0',
};

const featureCardTextStyle: React.CSSProperties = {
  color: '#555',
  lineHeight: '1.6',
  fontSize: '1rem',
};

const testimonialSectionStyle: React.CSSProperties = {
  backgroundColor: '#043a6b',
  padding: '80px 20px',
  textAlign: 'center',
  color: 'white',
};

const testimonialStyle: React.CSSProperties = {
  maxWidth: '800px',
  margin: '0 auto',
  position: 'relative',
};

const quoteIconStyle: React.CSSProperties = {
  fontSize: '2rem',
  opacity: '0.3',
  marginBottom: '20px',
};

const testimonialTextStyle: React.CSSProperties = {
  fontSize: '1.5rem',
  fontStyle: 'italic',
  lineHeight: '1.6',
  marginBottom: '20px',
};

const testimonialAuthorStyle: React.CSSProperties = {
  fontSize: '1.1rem',
  fontWeight: 'bold',
};

// Home Component
const Home: React.FC = () => {
  const { isAuthenticated } = useAuth();

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div style={homeContainerStyle}>
      <div style={heroSectionStyle} className="hero-section">
        <div style={heroContentStyle}>
          <h1 style={heroTitleStyle}>
            <span style={bankIconStyle}>🏦</span> Robin Bank
          </h1>
          <p style={heroSubtitleStyle}>
            Your Trusted Financial Partner
          </p>
          <div style={heroButtonsStyle}>
            <Link to="/login" style={primaryButtonStyle}>
              <i className="fas fa-sign-in-alt me-2"></i>Login
            </Link>
            <Link to="/register" style={secondaryButtonStyle}>
              <i className="fas fa-user-plus me-2"></i>Register
            </Link>
          </div>
        </div>
      </div>

      <div style={featuresContainerStyle}>
        <div style={sectionTitleContainerStyle}>
          <h2 style={sectionTitleStyle}>Why Choose Robin Bank?</h2>
          <div style={titleUnderlineStyle}></div>
        </div>
        
        <div style={featureCardsContainerStyle}>
          <div style={featureCardStyle} className="feature-card">
            <div style={featureIconContainerStyle} className="feature-icon-container">
              <i className="fas fa-shield-alt" style={featureIconStyle}></i>
            </div>
            <h3 style={featureCardTitleStyle}>Secure Banking</h3>
            <p style={featureCardTextStyle}>Advanced encryption and security features to protect your finances 24/7</p>
          </div>
          
          <div style={featureCardStyle} className="feature-card">
            <div style={featureIconContainerStyle} className="feature-icon-container">
              <i className="fas fa-mobile-alt" style={featureIconStyle}></i>
            </div>
            <h3 style={featureCardTitleStyle}>Easy Access</h3>
            <p style={featureCardTextStyle}>Access your account anytime, anywhere through our mobile and web platforms</p>
          </div>
          
          <div style={featureCardStyle} className="feature-card">
            <div style={featureIconContainerStyle} className="feature-icon-container">
              <i className="fas fa-chart-line" style={featureIconStyle}></i>
            </div>
            <h3 style={featureCardTitleStyle}>Financial Growth</h3>
            <p style={featureCardTextStyle}>Personalized investment options to help you grow your wealth</p>
          </div>
        </div>
      </div>
      
      <div style={testimonialSectionStyle}>
        <div style={{...sectionTitleContainerStyle, marginBottom: '2.5rem'}}>
          <h2 style={{...sectionTitleStyle, color: '#fff'}}>Our Customers Love Us</h2>
          <div style={{...titleUnderlineStyle, backgroundColor: '#fff'}}></div>
        </div>
        <div style={testimonialStyle} className="testimonial">
          <i className="fas fa-quote-left" style={quoteIconStyle}></i>
          <p style={testimonialTextStyle}>
            Robin Bank has transformed how I manage my finances. The security features and customer 
            service are unmatched in the industry!
          </p>
          <div style={testimonialAuthorStyle}>- Sarah Johnson, Customer since 2020</div>
        </div>
      </div>
    </div>
  );
};

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="App">
          <Navbar />
          <main>
            <Routes>
              {/* Public routes */}
              <Route path="/" element={<Home />} />
              <Route 
                path="/login" 
                element={
                  <PublicRoute>
                    <Login />
                  </PublicRoute>
                } 
              />
              <Route 
                path="/register" 
                element={
                  <PublicRoute>
                    <Register />
                  </PublicRoute>
                } 
              />
              
              {/* API Test route (for debugging) */}
              <Route 
                path="/api-test" 
                element={<ApiTest />} 
              />
              
              {/* Protected routes */}
              <Route 
                path="/dashboard" 
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                } 
              />
              
              <Route 
                path="/transactions" 
                element={
                  <ProtectedRoute>
                    <Transactions />
                  </ProtectedRoute>
                } 
              />
              
              {/* Catch all route */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
          <Footer />
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
