export interface User {
  _id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: 'admin' | 'user' | 'manager' | 'viewer';
  accountNumber: string;
  balance: number;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface LoginRequest {
  username: string; // Backend accepts username or email in this field
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  phoneNumber?: string;
}

export interface AuthResponse {
  success: boolean;
  message: string;
  data?: {
    user: User;
    token: string;
  };
}

export interface ApiError {
  message: string;
  details?: string;
}

// Transaction types
export interface Transaction {
  id: string;
  transactionId: string;
  type: 'transfer' | 'deposit' | 'withdrawal' | 'payment';
  amount: number;
  currency: string;
  description?: string;
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
  fromAccount?: {
    _id: string;
    username: string;
    accountNumber: string;
    firstName: string;
    lastName: string;
  };
  toAccount?: {
    _id: string;
    username: string;
    accountNumber: string;
    firstName: string;
    lastName: string;
  };
  externalAccount?: {
    accountNumber: string;
    bankName: string;
    routingNumber: string;
  };
  createdAt: string;
  processedAt?: string;
  fees?: number;
  riskScore?: number;
  isIncoming: boolean;
  authenticationMethod?: 'password' | 'mfa' | 'biometric';
  statusHistory?: Array<{
    status: string;
    timestamp: string;
    note?: string;
  }>;
}

export interface CreateTransactionRequest {
  type: 'transfer' | 'deposit' | 'withdrawal' | 'payment';
  amount: number;
  currency?: string;
  description?: string;
  toAccountNumber?: string;
  externalAccount?: {
    accountNumber: string;
    bankName: string;
    routingNumber: string;
  };
  authenticationMethod?: 'password' | 'mfa' | 'biometric';
  paymentMethodId?: string;
}

export interface TransactionFilters {
  page?: number;
  limit?: number;
  type?: string;
  status?: string;
  startDate?: string;
  endDate?: string;
  minAmount?: number;
  maxAmount?: number;
}

export interface TransactionsResponse {
  transactions: Transaction[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}