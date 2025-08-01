import React, { useState, FormEvent, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import SimpleCaptcha from '../components/SimpleCaptcha';
import axios from 'axios';
import './Auth.css';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const { login, isLoading, error, clearError } = useAuth();
  
  const [formData, setFormData] = useState({
    username: '',
    password: '',
  });

  const [validationErrors, setValidationErrors] = useState<{[key: string]: string}>({});
  const [captchaToken, setCaptchaToken] = useState('');
  const [requireCaptcha, setRequireCaptcha] = useState(false);

  // Check if CAPTCHA is required on component mount
  useEffect(() => {
    const checkCaptchaRequired = async () => {
      try {
        const response = await axios.get('/api/auth/captcha-required');
        setRequireCaptcha(response.data.requireCaptcha);
      } catch (error) {
        console.error('Failed to check CAPTCHA requirement:', error);
        // Default to requiring CAPTCHA on error for security
        setRequireCaptcha(true);
      }
    };

    checkCaptchaRequired();
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear validation error when user starts typing
    if (validationErrors[name]) {
      setValidationErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
    
    // Clear global error
    if (error) {
      clearError();
    }
  };

  const validateForm = (): boolean => {
    const errors: {[key: string]: string} = {};

    if (!formData.username.trim()) {
      errors.username = 'Username or email is required';
    }

    if (!formData.password) {
      errors.password = 'Password is required';
    }

    if (requireCaptcha && !captchaToken) {
      errors.captcha = 'Please complete the CAPTCHA verification';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleCaptchaVerify = (token: string) => {
    setCaptchaToken(token);
    // Clear captcha validation error when user completes CAPTCHA
    if (validationErrors.captcha) {
      setValidationErrors(prev => ({
        ...prev,
        captcha: ''
      }));
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    try {
      const loginData: any = {
        username: formData.username, // Backend accepts username or email in this field
        password: formData.password,
      };

      // Include CAPTCHA token if required
      if (requireCaptcha && captchaToken) {
        loginData.captchaToken = captchaToken;
      }

      await login(loginData);
      navigate('/dashboard');
    } catch (error: any) {
      // If server indicates CAPTCHA is required, update state
      if (error.response?.data?.requireCaptcha) {
        setRequireCaptcha(true);
      }
      console.error('Login failed:', error);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h2>Sign In</h2>
          <p>Welcome back! Please sign in to your account.</p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          {error && (
            <div className="error-message" role="alert">
              {error}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="username">Username or Email</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              className={validationErrors.username ? 'error' : ''}
              placeholder="Enter your username or email"
              autoComplete="username"
              required
            />
            {validationErrors.username && (
              <span className="field-error">{validationErrors.username}</span>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              className={validationErrors.password ? 'error' : ''}
              placeholder="Enter your password"
              autoComplete="current-password"
              required
            />
            {validationErrors.password && (
              <span className="field-error">{validationErrors.password}</span>
            )}
          </div>

          {/* CAPTCHA Component */}
          <SimpleCaptcha 
            onVerify={handleCaptchaVerify}
            required={requireCaptcha}
            className="mb-3"
          />
          {validationErrors.captcha && (
            <div className="field-error mb-3">{validationErrors.captcha}</div>
          )}

          <div className="form-actions">
            <button 
              type="submit" 
              className="btn-primary"
              disabled={isLoading}
            >
              {isLoading ? 'Signing In...' : 'Sign In'}
            </button>
          </div>

          <div className="auth-links">
            <Link to="/forgot-password" className="forgot-password-link">
              Forgot your password?
            </Link>
          </div>
        </form>

        <div className="auth-footer">
          <p>
            Don't have an account?{' '}
            <Link to="/register" className="auth-link">
              Sign up here
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
