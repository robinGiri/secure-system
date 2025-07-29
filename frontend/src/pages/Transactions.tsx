import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Button, Table, Badge, Alert, Modal, Form, Spinner } from 'react-bootstrap';
import { apiService } from '../services/api';
import { Transaction, CreateTransactionRequest, TransactionFilters } from '../types';
import { useAuth } from '../contexts/AuthContext';
import TransactionForm from '../components/TransactionForm';

interface TransactionPageState {
  transactions: Transaction[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
  loading: boolean;
  error: string | null;
  showCreateModal: boolean;
  balance: number;
  selectedTransaction: Transaction | null;
  showDetailsModal: boolean;
}

const Transactions: React.FC = () => {
  const { user } = useAuth();
  const [state, setState] = useState<TransactionPageState>({
    transactions: [],
    pagination: { page: 1, limit: 20, total: 0, pages: 0 },
    loading: true,
    error: null,
    showCreateModal: false,
    balance: 0,
    selectedTransaction: null,
    showDetailsModal: false
  });

  const [filters, setFilters] = useState<TransactionFilters>({
    page: 1,
    limit: 20
  });

  const [formLoading, setFormLoading] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Load transactions and balance
  useEffect(() => {
    const loadTransactions = async () => {
      try {
        setState(prev => ({ ...prev, loading: true, error: null }));
        
        const response = await apiService.getTransactions(filters);
        
        if (response.success && response.data) {
          setState(prev => ({
            ...prev,
            transactions: response.data!.transactions,
            pagination: response.data!.pagination,
            loading: false
          }));
        } else {
          setState(prev => ({
            ...prev,
            error: response.message || 'Failed to load transactions',
            loading: false
          }));
        }
      } catch (error) {
        setState(prev => ({
          ...prev,
          error: error instanceof Error ? error.message : 'Failed to load transactions',
          loading: false
        }));
      }
    };

    const loadBalance = async () => {
      try {
        const response = await apiService.getUserBalance();
        if (response.success && response.data) {
          setState(prev => ({ ...prev, balance: response.data!.balance }));
        }
      } catch (error) {
        console.error('Failed to load balance:', error);
      }
    };

    loadTransactions();
    loadBalance();
  }, [filters]);

  const loadTransactions = async () => {
    try {
      setState(prev => ({ ...prev, loading: true, error: null }));
      
      const response = await apiService.getTransactions(filters);
      
      if (response.success && response.data) {
        setState(prev => ({
          ...prev,
          transactions: response.data!.transactions,
          pagination: response.data!.pagination,
          loading: false
        }));
      } else {
        setState(prev => ({
          ...prev,
          error: response.message || 'Failed to load transactions',
          loading: false
        }));
      }
    } catch (error) {
      setState(prev => ({
        ...prev,
        error: error instanceof Error ? error.message : 'Failed to load transactions',
        loading: false
      }));
    }
  };

  const loadBalance = async () => {
    try {
      const response = await apiService.getUserBalance();
      if (response.success && response.data) {
        setState(prev => ({ ...prev, balance: response.data!.balance }));
      }
    } catch (error) {
      console.error('Failed to load balance:', error);
    }
  };

  const handleCreateTransaction = async (transactionData: CreateTransactionRequest) => {
    setFormLoading(true);
    setFormError(null);

    try {
      const response = await apiService.createTransaction(transactionData);
      
      if (response.success) {
        setState(prev => ({ ...prev, showCreateModal: false }));
        
        // Reload transactions and balance
        await loadTransactions();
        await loadBalance();
        
        alert('Transaction created successfully!');
      } else {
        setFormError(response.message || 'Failed to create transaction');
        throw new Error(response.message || 'Failed to create transaction');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to create transaction';
      setFormError(errorMessage);
      throw error; // Re-throw to let TransactionForm handle it
    } finally {
      setFormLoading(false);
    }
  };

  const handleViewDetails = async (transaction: Transaction) => {
    try {
      const response = await apiService.getTransaction(transaction.transactionId);
      if (response.success && response.data) {
        setState(prev => ({
          ...prev,
          selectedTransaction: response.data!.transaction,
          showDetailsModal: true
        }));
      }
    } catch (error) {
      alert('Failed to load transaction details');
    }
  };

  const handleCancelTransaction = async (transactionId: string) => {
    if (!window.confirm('Are you sure you want to cancel this transaction?')) {
      return;
    }

    try {
      const response = await apiService.cancelTransaction(transactionId);
      if (response.success) {
        alert('Transaction cancelled successfully');
        await loadTransactions();
      } else {
        alert(response.message || 'Failed to cancel transaction');
      }
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Failed to cancel transaction');
    }
  };

  const getStatusBadge = (status: string) => {
    const variants: { [key: string]: string } = {
      'pending': 'warning',
      'processing': 'info',
      'completed': 'success',
      'failed': 'danger',
      'cancelled': 'secondary'
    };
    return <Badge bg={variants[status] || 'secondary'}>{status.toUpperCase()}</Badge>;
  };

  const getTransactionTypeIcon = (type: string) => {
    const icons: { [key: string]: string } = {
      'transfer': 'fas fa-exchange-alt',
      'deposit': 'fas fa-plus-circle',
      'withdrawal': 'fas fa-minus-circle',
      'payment': 'fas fa-credit-card'
    };
    return <i className={`${icons[type] || 'fas fa-circle'} me-2`}></i>;
  };

  const formatCurrency = (amount: number, currency: string = 'USD') => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency
    }).format(amount);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  if (state.loading && state.transactions.length === 0) {
    return (
      <Container className="mt-4">
        <div className="text-center">
          <Spinner animation="border" role="status">
            <span className="visually-hidden">Loading...</span>
          </Spinner>
          <p className="mt-2">Loading transactions...</p>
        </div>
      </Container>
    );
  }

  return (
    <Container className="mt-4">
      <Row>
        <Col>
          <div className="d-flex justify-content-between align-items-center mb-4">
            <h2>
              <i className="fas fa-exchange-alt me-2"></i>
              Transactions
            </h2>
            <Button 
              variant="primary" 
              onClick={() => setState(prev => ({ ...prev, showCreateModal: true }))}
            >
              <i className="fas fa-plus me-2"></i>
              New Transaction
            </Button>
          </div>

          {/* Balance Card */}
          <Card className="mb-4">
            <Card.Body>
              <Row>
                <Col md={6}>
                  <h5 className="mb-0">Account Balance</h5>
                  <h3 className="text-primary mb-0">{formatCurrency(state.balance)}</h3>
                  <small className="text-muted">Available Balance</small>
                </Col>
                <Col md={6} className="text-md-end">
                  <p className="mb-1">Account: {user?.accountNumber}</p>
                  <p className="mb-0 text-muted">
                    Last updated: {new Date().toLocaleString()}
                  </p>
                </Col>
              </Row>
            </Card.Body>
          </Card>

          {/* Filters */}
          <Card className="mb-4">
            <Card.Body>
              <Row>
                <Col md={3}>
                  <Form.Group>
                    <Form.Label>Transaction Type</Form.Label>
                    <Form.Select
                      value={filters.type || ''}
                      onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilters(prev => ({ ...prev, type: e.target.value || undefined, page: 1 }))}
                    >
                      <option value="">All Types</option>
                      <option value="transfer">Transfer</option>
                      <option value="deposit">Deposit</option>
                      <option value="withdrawal">Withdrawal</option>
                      <option value="payment">Payment</option>
                    </Form.Select>
                  </Form.Group>
                </Col>
                <Col md={3}>
                  <Form.Group>
                    <Form.Label>Status</Form.Label>
                    <Form.Select
                      value={filters.status || ''}
                      onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilters(prev => ({ ...prev, status: e.target.value || undefined, page: 1 }))}
                    >
                      <option value="">All Statuses</option>
                      <option value="pending">Pending</option>
                      <option value="processing">Processing</option>
                      <option value="completed">Completed</option>
                      <option value="failed">Failed</option>
                      <option value="cancelled">Cancelled</option>
                    </Form.Select>
                  </Form.Group>
                </Col>
                <Col md={3}>
                  <Form.Group>
                    <Form.Label>Min Amount</Form.Label>
                    <Form.Control
                      type="number"
                      step="0.01"
                      value={filters.minAmount || ''}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters(prev => ({ 
                        ...prev, 
                        minAmount: e.target.value ? parseFloat(e.target.value) : undefined,
                        page: 1 
                      }))}
                    />
                  </Form.Group>
                </Col>
                <Col md={3}>
                  <Form.Group>
                    <Form.Label>Max Amount</Form.Label>
                    <Form.Control
                      type="number"
                      step="0.01"
                      value={filters.maxAmount || ''}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFilters(prev => ({ 
                        ...prev, 
                        maxAmount: e.target.value ? parseFloat(e.target.value) : undefined,
                        page: 1 
                      }))}
                    />
                  </Form.Group>
                </Col>
              </Row>
            </Card.Body>
          </Card>

          {state.error && (
            <Alert variant="danger" className="mb-4">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {state.error}
            </Alert>
          )}

          {/* Transactions Table */}
          <Card>
            <Card.Body>
              {state.transactions.length === 0 ? (
                <div className="text-center py-5">
                  <i className="fas fa-receipt fa-3x text-muted mb-3"></i>
                  <h5>No transactions found</h5>
                  <p className="text-muted">You haven't made any transactions yet.</p>
                </div>
              ) : (
                <>
                  <Table responsive hover>
                    <thead>
                      <tr>
                        <th>Date</th>
                        <th>Type</th>
                        <th>Description</th>
                        <th>Amount</th>
                        <th>Status</th>
                        <th>Account</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {state.transactions.map((transaction) => (
                        <tr key={transaction.id}>
                          <td>
                            <small>{formatDate(transaction.createdAt)}</small>
                          </td>
                          <td>
                            {getTransactionTypeIcon(transaction.type)}
                            {transaction.type.charAt(0).toUpperCase() + transaction.type.slice(1)}
                          </td>
                          <td>
                            {transaction.description || 'No description'}
                            <br />
                            <small className="text-muted">ID: {transaction.transactionId}</small>
                          </td>
                          <td>
                            <span className={transaction.isIncoming ? 'text-success' : 'text-danger'}>
                              {transaction.isIncoming ? '+' : '-'}
                              {formatCurrency(transaction.amount, transaction.currency)}
                            </span>
                            {transaction.fees && transaction.fees > 0 && (
                              <><br /><small className="text-muted">Fee: {formatCurrency(transaction.fees)}</small></>
                            )}
                          </td>
                          <td>{getStatusBadge(transaction.status)}</td>
                          <td>
                            {transaction.isIncoming ? (
                              <>
                                <strong>From:</strong> {transaction.fromAccount?.accountNumber}<br />
                                <small>{transaction.fromAccount?.firstName} {transaction.fromAccount?.lastName}</small>
                              </>
                            ) : (
                              <>
                                <strong>To:</strong> {transaction.toAccount?.accountNumber}<br />
                                <small>{transaction.toAccount?.firstName} {transaction.toAccount?.lastName}</small>
                              </>
                            )}
                          </td>
                          <td>
                            <Button
                              variant="outline-primary"
                              size="sm"
                              className="me-2"
                              onClick={() => handleViewDetails(transaction)}
                            >
                              <i className="fas fa-eye"></i>
                            </Button>
                            {transaction.status === 'pending' && !transaction.isIncoming && (
                              <Button
                                variant="outline-danger"
                                size="sm"
                                onClick={() => handleCancelTransaction(transaction.transactionId)}
                              >
                                <i className="fas fa-times"></i>
                              </Button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>

                  {/* Pagination */}
                  {state.pagination.pages > 1 && (
                    <div className="d-flex justify-content-between align-items-center mt-3">
                      <div>
                        Showing {((state.pagination.page - 1) * state.pagination.limit) + 1} to{' '}
                        {Math.min(state.pagination.page * state.pagination.limit, state.pagination.total)} of{' '}
                        {state.pagination.total} transactions
                      </div>
                      <div>
                        <Button
                          variant="outline-primary"
                          size="sm"
                          disabled={state.pagination.page <= 1}
                          onClick={() => setFilters(prev => ({ ...prev, page: prev.page! - 1 }))}
                          className="me-2"
                        >
                          Previous
                        </Button>
                        <span className="mx-2">
                          Page {state.pagination.page} of {state.pagination.pages}
                        </span>
                        <Button
                          variant="outline-primary"
                          size="sm"
                          disabled={state.pagination.page >= state.pagination.pages}
                          onClick={() => setFilters(prev => ({ ...prev, page: prev.page! + 1 }))}
                          className="ms-2"
                        >
                          Next
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Create Transaction Modal */}
      <TransactionForm
        show={state.showCreateModal}
        onHide={() => setState(prev => ({ ...prev, showCreateModal: false }))}
        onSubmit={handleCreateTransaction}
        loading={formLoading}
        error={formError}
      />

      {/* Transaction Details Modal */}
      <Modal 
        show={state.showDetailsModal} 
        onHide={() => setState(prev => ({ ...prev, showDetailsModal: false, selectedTransaction: null }))}
        size="lg"
      >
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="fas fa-receipt me-2"></i>
            Transaction Details
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {state.selectedTransaction && (
            <Row>
              <Col md={6}>
                <h6>Transaction Information</h6>
                <table className="table table-sm">
                  <tbody>
                    <tr>
                      <td><strong>ID:</strong></td>
                      <td>{state.selectedTransaction.transactionId}</td>
                    </tr>
                    <tr>
                      <td><strong>Type:</strong></td>
                      <td>
                        {getTransactionTypeIcon(state.selectedTransaction.type)}
                        {state.selectedTransaction.type.charAt(0).toUpperCase() + state.selectedTransaction.type.slice(1)}
                      </td>
                    </tr>
                    <tr>
                      <td><strong>Amount:</strong></td>
                      <td className={state.selectedTransaction.isIncoming ? 'text-success' : 'text-danger'}>
                        {state.selectedTransaction.isIncoming ? '+' : '-'}
                        {formatCurrency(state.selectedTransaction.amount, state.selectedTransaction.currency)}
                      </td>
                    </tr>
                    <tr>
                      <td><strong>Status:</strong></td>
                      <td>{getStatusBadge(state.selectedTransaction.status)}</td>
                    </tr>
                    <tr>
                      <td><strong>Created:</strong></td>
                      <td>{formatDate(state.selectedTransaction.createdAt)}</td>
                    </tr>
                    {state.selectedTransaction.processedAt && (
                      <tr>
                        <td><strong>Processed:</strong></td>
                        <td>{formatDate(state.selectedTransaction.processedAt)}</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </Col>
              <Col md={6}>
                <h6>Account Information</h6>
                <table className="table table-sm">
                  <tbody>
                    {state.selectedTransaction.fromAccount && (
                      <>
                        <tr>
                          <td><strong>From Account:</strong></td>
                          <td>{state.selectedTransaction.fromAccount.accountNumber}</td>
                        </tr>
                        <tr>
                          <td><strong>From Name:</strong></td>
                          <td>{state.selectedTransaction.fromAccount.firstName} {state.selectedTransaction.fromAccount.lastName}</td>
                        </tr>
                      </>
                    )}
                    {state.selectedTransaction.toAccount && (
                      <>
                        <tr>
                          <td><strong>To Account:</strong></td>
                          <td>{state.selectedTransaction.toAccount.accountNumber}</td>
                        </tr>
                        <tr>
                          <td><strong>To Name:</strong></td>
                          <td>{state.selectedTransaction.toAccount.firstName} {state.selectedTransaction.toAccount.lastName}</td>
                        </tr>
                      </>
                    )}
                    {state.selectedTransaction.fees && state.selectedTransaction.fees > 0 && (
                      <tr>
                        <td><strong>Fees:</strong></td>
                        <td>{formatCurrency(state.selectedTransaction.fees)}</td>
                      </tr>
                    )}
                    {state.selectedTransaction.riskScore && (
                      <tr>
                        <td><strong>Risk Score:</strong></td>
                        <td>
                          <Badge bg={state.selectedTransaction.riskScore > 70 ? 'danger' : state.selectedTransaction.riskScore > 40 ? 'warning' : 'success'}>
                            {state.selectedTransaction.riskScore}/100
                          </Badge>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </Col>
              {state.selectedTransaction.description && (
                <Col xs={12}>
                  <h6>Description</h6>
                  <p className="bg-light p-3 rounded">{state.selectedTransaction.description}</p>
                </Col>
              )}
            </Row>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button 
            variant="secondary" 
            onClick={() => setState(prev => ({ ...prev, showDetailsModal: false, selectedTransaction: null }))}
          >
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};

export default Transactions;
