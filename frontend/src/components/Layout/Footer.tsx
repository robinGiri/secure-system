import React from 'react';
import { Link } from 'react-router-dom';
import './Footer.css';

const Footer: React.FC = () => {
  return (
    <footer style={footerStyle}>
      <div style={footerContainerStyle}>
        <div style={footerSectionStyle}>
          <div style={footerBrandStyle}>
            <div style={logoStyle}>
              <span style={logoIconStyle}>🏦</span>
              <span style={logoTextStyle}>Robin Bank</span>
            </div>
            <p style={taglineStyle}>Your trusted financial partner</p>
            <p style={copyrightStyle}>© {new Date().getFullYear()} Robin Bank. All rights reserved.</p>
          </div>
        </div>

        <div style={footerSectionStyle}>
          <h3 style={footerHeadingStyle} className="footer-heading">Quick Links</h3>
          <ul style={footerListStyle}>
            <li style={footerListItemStyle}>
              <Link to="/" style={footerLinkStyle} className="footer-link">Home</Link>
            </li>
            <li style={footerListItemStyle}>
              <Link to="/about" style={footerLinkStyle} className="footer-link">About</Link>
            </li>
            <li style={footerListItemStyle}>
              <Link to="/services" style={footerLinkStyle} className="footer-link">Services</Link>
            </li>
            <li style={footerListItemStyle}>
              <Link to="/contact" style={footerLinkStyle} className="footer-link">Contact</Link>
            </li>
          </ul>
        </div>

        <div style={footerSectionStyle}>
          <h3 style={footerHeadingStyle} className="footer-heading">Services</h3>
          <ul style={footerListStyle}>
            <li style={footerListItemStyle}>
              <Link to="/services/checking" style={footerLinkStyle} className="footer-link">Checking Accounts</Link>
            </li>
            <li style={footerListItemStyle}>
              <Link to="/services/savings" style={footerLinkStyle} className="footer-link">Savings Accounts</Link>
            </li>
            <li style={footerListItemStyle}>
              <Link to="/services/loans" style={footerLinkStyle} className="footer-link">Loans</Link>
            </li>
            <li style={footerListItemStyle}>
              <Link to="/services/investments" style={footerLinkStyle} className="footer-link">Investments</Link>
            </li>
          </ul>
        </div>

        <div style={footerSectionStyle}>
          <h3 style={footerHeadingStyle} className="footer-heading">Contact Us</h3>
          <address style={addressStyle}>
            <p style={contactItemStyle}>
              <i className="fas fa-map-marker-alt" style={contactIconStyle}></i> 
              123 Financial Ave, Banking District
            </p>
            <p style={contactItemStyle}>
              <i className="fas fa-phone" style={contactIconStyle}></i> 
              (800) 555-BANK
            </p>
            <p style={contactItemStyle}>
              <i className="fas fa-envelope" style={contactIconStyle}></i> 
              support@robinbank.com
            </p>
          </address>
          <div style={socialLinksStyle}>
            <a href="https://facebook.com" style={socialLinkStyle} aria-label="Facebook" className="social-link">
              <i className="fab fa-facebook-f"></i>
            </a>
            <a href="https://twitter.com" style={socialLinkStyle} aria-label="Twitter" className="social-link">
              <i className="fab fa-twitter"></i>
            </a>
            <a href="https://linkedin.com" style={socialLinkStyle} aria-label="LinkedIn" className="social-link">
              <i className="fab fa-linkedin-in"></i>
            </a>
            <a href="https://instagram.com" style={socialLinkStyle} aria-label="Instagram" className="social-link">
              <i className="fab fa-instagram"></i>
            </a>
          </div>
        </div>
      </div>

      <div style={bottomBarStyle}>
        <div style={bottomBarContainerStyle}>
          <p style={bottomBarTextStyle}>
            Robin Bank is a secure financial institution. All transactions are encrypted.
          </p>
          <div style={legalLinksStyle}>
            <Link to="/privacy" style={legalLinkStyle} className="footer-link">Privacy Policy</Link>
            <Link to="/terms" style={legalLinkStyle} className="footer-link">Terms of Service</Link>
            <Link to="/security" style={legalLinkStyle} className="footer-link">Security</Link>
          </div>
        </div>
      </div>
    </footer>
  );
};

// Footer Styles
const footerStyle: React.CSSProperties = {
  backgroundColor: '#043a6b',
  color: 'white',
  padding: '60px 0 0',
  fontFamily: "'Poppins', sans-serif",
};

const footerContainerStyle: React.CSSProperties = {
  maxWidth: '1200px',
  margin: '0 auto',
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
  gap: '40px',
  padding: '0 20px',
};

const footerSectionStyle: React.CSSProperties = {
  marginBottom: '20px',
};

const footerBrandStyle: React.CSSProperties = {
  marginBottom: '20px',
};

const logoStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  marginBottom: '10px',
};

const logoIconStyle: React.CSSProperties = {
  fontSize: '1.75rem',
  marginRight: '8px',
};

const logoTextStyle: React.CSSProperties = {
  fontSize: '1.5rem',
  fontWeight: 'bold',
  color: '#ffffff',
};

const taglineStyle: React.CSSProperties = {
  fontSize: '0.9rem',
  color: '#a3c2e3',
  marginBottom: '15px',
};

const copyrightStyle: React.CSSProperties = {
  fontSize: '0.85rem',
  color: '#a3c2e3',
};

const footerHeadingStyle: React.CSSProperties = {
  fontSize: '1.1rem',
  fontWeight: '600',
  marginBottom: '20px',
  position: 'relative',
  paddingBottom: '10px',
};

const footerListStyle: React.CSSProperties = {
  listStyle: 'none',
  padding: 0,
  margin: 0,
};

const footerListItemStyle: React.CSSProperties = {
  marginBottom: '12px',
};

const footerLinkStyle: React.CSSProperties = {
  color: '#e0e7ff',
  textDecoration: 'none',
  fontSize: '0.9rem',
  transition: 'color 0.3s ease',
  position: 'relative',
};

const addressStyle: React.CSSProperties = {
  fontStyle: 'normal',
  marginBottom: '20px',
};

const contactItemStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  fontSize: '0.9rem',
  marginBottom: '10px',
  color: '#e0e7ff',
};

const contactIconStyle: React.CSSProperties = {
  marginRight: '10px',
  color: '#4caf50',
};

const socialLinksStyle: React.CSSProperties = {
  display: 'flex',
  gap: '15px',
};

const socialLinkStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: '36px',
  height: '36px',
  borderRadius: '50%',
  backgroundColor: 'rgba(255, 255, 255, 0.1)',
  color: 'white',
  transition: 'all 0.3s ease',
};

const bottomBarStyle: React.CSSProperties = {
  borderTop: '1px solid rgba(255, 255, 255, 0.1)',
  marginTop: '40px',
  padding: '20px 0',
};

const bottomBarContainerStyle: React.CSSProperties = {
  maxWidth: '1200px',
  margin: '0 auto',
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  padding: '0 20px',
  flexWrap: 'wrap',
  gap: '20px',
};

const bottomBarTextStyle: React.CSSProperties = {
  fontSize: '0.85rem',
  color: '#a3c2e3',
  margin: 0,
};

const legalLinksStyle: React.CSSProperties = {
  display: 'flex',
  gap: '20px',
};

const legalLinkStyle: React.CSSProperties = {
  fontSize: '0.85rem',
  color: '#a3c2e3',
  textDecoration: 'none',
  transition: 'color 0.3s ease',
};

export default Footer;
