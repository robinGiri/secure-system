// API service for handling HTTP requests
import { LoginRequest, RegisterRequest, User, Transaction, CreateTransactionRequest, TransactionFilters, TransactionsResponse } from '../types';

// For development with proxy in package.json, we can use relative URLs
// In production, we'll use the full URL from environment variable
const API_BASE_URL = process.env.NODE_ENV === 'development' 
  ? '' // Use relative URL with proxy in development
  : (process.env.REACT_APP_API_URL || 'http://localhost:3000');

// Debug logging for environment
console.log('API Service initialized with base URL:', API_BASE_URL || '(using proxy)');
console.log('Environment variables:', {
  REACT_APP_API_URL: process.env.REACT_APP_API_URL,
  NODE_ENV: process.env.NODE_ENV
});

interface ApiResponse<T> {
  success: boolean;
  message: string;
  data?: T;
  errors?: Array<{ field: string; message: string }>;
}

class ApiService {
  // Test connectivity to the backend
  async testConnection(): Promise<boolean> {
    try {
      console.log('Testing connection to:', `${API_BASE_URL}/api/auth/login`);
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: 'OPTIONS', // Preflight request
        headers: {
          'Origin': window.location.origin,
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type'
        }
      });
      console.log('Connection test response:', response.status, response.statusText);
      return response.ok;
    } catch (error) {
      console.error('Connection test failed:', error);
      return false;
    }
  }

  private getHeaders(includeAuth = false): HeadersInit {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };

    if (includeAuth) {
      const token = localStorage.getItem('authToken');
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
    }

    return headers;
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    let data;
    const contentType = response.headers.get('content-type');
    
    try {
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        // If response is not JSON, get text for better error reporting
        const text = await response.text();
        console.error('Non-JSON response:', text);
        data = { message: `Server returned non-JSON response: ${response.status} ${response.statusText}` };
      }
    } catch (parseError) {
      console.error('Failed to parse response:', parseError);
      data = { message: `Failed to parse server response: ${response.status} ${response.statusText}` };
    }
    
    if (!response.ok) {
      console.error('API Error:', {
        status: response.status,
        statusText: response.statusText,
        url: response.url,
        data
      });
      throw new Error(data.message || `HTTP ${response.status}: ${response.statusText}`);
    }

    return data;
  }

  // Authentication endpoints
  async login(credentials: LoginRequest): Promise<ApiResponse<{ user: User; token: string }>> {
    // When using proxy in development, we can use relative URL path
    const loginUrl = `${API_BASE_URL}/api/auth/login`;
    console.log('API: Attempting login to:', loginUrl);
    console.log('API: Current API_BASE_URL:', API_BASE_URL || '(using proxy)');
    console.log('API: Environment NODE_ENV:', process.env.NODE_ENV);
    console.log('API: Environment REACT_APP_API_URL:', process.env.REACT_APP_API_URL);
    console.log('API: Credentials being sent:', { username: credentials.username, hasPassword: !!credentials.password });
    
    try {
      const response = await fetch(loginUrl, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(credentials),
        credentials: 'include',  // Include cookies for session management
      });

      console.log('API: Response received:', {
        status: response.status,
        statusText: response.statusText,
        url: response.url,
        headers: Object.fromEntries(response.headers.entries())
      });

      return this.handleResponse<ApiResponse<{ user: User; token: string }>>(response);
    } catch (error) {
      console.error('Login fetch error:', error);
      throw error;
    }
  }

  async register(userData: RegisterRequest): Promise<ApiResponse<{ userId: string; username: string; email: string; accountNumber: string }>> {
    console.log('API: Attempting registration to:', `${API_BASE_URL}/api/auth/register`);
    console.log('API: Registration data:', { ...userData, password: '[REDACTED]' });
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(userData),
        // Remove credentials: 'include' temporarily to test
      });

      return this.handleResponse<ApiResponse<{ userId: string; username: string; email: string; accountNumber: string }>>(response);
    } catch (error) {
      console.error('Registration fetch error:', error);
      console.error('Error details:', {
        message: error instanceof Error ? error.message : 'Unknown error',
        type: typeof error,
        stack: error instanceof Error ? error.stack : 'No stack trace'
      });
      
      // Provide more detailed error information
      if (error instanceof TypeError && error.message === 'Failed to fetch') {
        throw new Error('Unable to connect to server. Please check if the backend server is running on http://localhost:3000');
      }
      throw error;
    }
  }

  async logout(): Promise<ApiResponse<null>> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/logout`, {
        method: 'POST',
        headers: this.getHeaders(true),
        credentials: 'include',
      });

      return this.handleResponse<ApiResponse<null>>(response);
    } catch (error) {
      console.error('Logout fetch error:', error);
      throw error;
    }
  }

  async getCurrentUser(): Promise<ApiResponse<User>> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/me`, {
        method: 'GET',
        headers: this.getHeaders(true),
        credentials: 'include',
      });

      return this.handleResponse<ApiResponse<User>>(response);
    } catch (error) {
      console.error('Get current user fetch error:', error);
      throw error;
    }
  }

  // Transaction endpoints
  async getTransactions(filters?: TransactionFilters): Promise<ApiResponse<TransactionsResponse>> {
    try {
      const queryParams = new URLSearchParams();
      
      if (filters) {
        Object.entries(filters).forEach(([key, value]) => {
          if (value !== undefined && value !== null) {
            queryParams.append(key, String(value));
          }
        });
      }
      
      const queryString = queryParams.toString();
      const url = `${API_BASE_URL}/api/transactions${queryString ? `?${queryString}` : ''}`;
      
      const response = await fetch(url, {
        method: 'GET',
        headers: this.getHeaders(true),
        credentials: 'include',
      });

      return this.handleResponse<ApiResponse<TransactionsResponse>>(response);
    } catch (error) {
      console.error('Get transactions fetch error:', error);
      throw error;
    }
  }

  async getTransaction(transactionId: string): Promise<ApiResponse<{ transaction: Transaction }>> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/transactions/${transactionId}`, {
        method: 'GET',
        headers: this.getHeaders(true),
        credentials: 'include',
      });

      return this.handleResponse<ApiResponse<{ transaction: Transaction }>>(response);
    } catch (error) {
      console.error('Get transaction fetch error:', error);
      throw error;
    }
  }

  async createTransaction(transactionData: CreateTransactionRequest): Promise<ApiResponse<{ transaction: Transaction }>> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/transactions`, {
        method: 'POST',
        headers: this.getHeaders(true),
        body: JSON.stringify(transactionData),
        credentials: 'include',
      });

      return this.handleResponse<ApiResponse<{ transaction: Transaction }>>(response);
    } catch (error) {
      console.error('Create transaction fetch error:', error);
      throw error;
    }
  }

  async cancelTransaction(transactionId: string): Promise<ApiResponse<{ transaction: Transaction }>> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/transactions/${transactionId}/cancel`, {
        method: 'POST',
        headers: this.getHeaders(true),
        credentials: 'include',
      });

      return this.handleResponse<ApiResponse<{ transaction: Transaction }>>(response);
    } catch (error) {
      console.error('Cancel transaction fetch error:', error);
      throw error;
    }
  }

  // User balance endpoint
  async getUserBalance(): Promise<ApiResponse<{ balance: number; currency: string }>> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/user/balance`, {
        method: 'GET',
        headers: this.getHeaders(true),
        credentials: 'include',
      });

      return this.handleResponse<ApiResponse<{ balance: number; currency: string }>>(response);
    } catch (error) {
      console.error('Get user balance fetch error:', error);
      throw error;
    }
  }
}

export const apiService = new ApiService();
export default apiService;