import React, { useState } from 'react';
import { Modal, Form, Button, Alert, Spinner, Row, Col } from 'react-bootstrap';
import { CreateTransactionRequest } from '../types';

interface TransactionFormProps {
  show: boolean;
  onHide: () => void;
  onSubmit: (transaction: CreateTransactionRequest) => Promise<void>;
  loading?: boolean;
  error?: string | null;
}

const TransactionForm: React.FC<TransactionFormProps> = ({
  show,
  onHide,
  onSubmit,
  loading = false,
  error = null
}) => {
  const [formData, setFormData] = useState<CreateTransactionRequest>({
    type: 'transfer',
    amount: 0,
    currency: 'USD',
    description: '',
    toAccountNumber: '',
    authenticationMethod: 'mfa'
  });

  const [validated, setValidated] = useState(false);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    e.stopPropagation();

    const form = e.currentTarget;
    if (form.checkValidity() === false) {
      setValidated(true);
      return;
    }

    try {
      await onSubmit(formData);
      
      // Reset form on success
      setFormData({
        type: 'transfer',
        amount: 0,
        currency: 'USD',
        description: '',
        toAccountNumber: '',
        authenticationMethod: 'mfa'
      });
      setValidated(false);
    } catch (error) {
      // Error handling is done by parent component
    }
  };

  const handleChange = (field: keyof CreateTransactionRequest, value: any) => {
    setFormData((prev: CreateTransactionRequest) => ({
      ...prev,
      [field]: value
    }));
  };

  const resetForm = () => {
    setFormData({
      type: 'transfer',
      amount: 0,
      currency: 'USD',
      description: '',
      toAccountNumber: '',
      authenticationMethod: 'mfa'
    });
    setValidated(false);
  };

  const handleClose = () => {
    resetForm();
    onHide();
  };

  return (
    <Modal show={show} onHide={handleClose} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>
          <i className="fas fa-plus me-2"></i>
          Create New Transaction
        </Modal.Title>
      </Modal.Header>

      <Form noValidate validated={validated} onSubmit={handleSubmit}>
        <Modal.Body>
          {error && (
            <Alert variant="danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
            </Alert>
          )}

          <Row>
            <Col md={6}>
              <Form.Group className="mb-3">
                <Form.Label>Transaction Type *</Form.Label>
                <Form.Select
                  value={formData.type}
                  onChange={(e) => handleChange('type', e.target.value as 'transfer' | 'deposit' | 'withdrawal' | 'payment')}
                  required
                >
                  <option value="transfer">Transfer Money</option>
                  <option value="deposit">Deposit Funds</option>
                  <option value="withdrawal">Withdraw Funds</option>
                  <option value="payment">Make Payment</option>
                </Form.Select>
                <Form.Control.Feedback type="invalid">
                  Please select a transaction type.
                </Form.Control.Feedback>
              </Form.Group>
            </Col>

            <Col md={6}>
              <Form.Group className="mb-3">
                <Form.Label>Amount (USD) *</Form.Label>
                <Form.Control
                  type="number"
                  step="0.01"
                  min="0.01"
                  max="1000000"
                  value={formData.amount || ''}
                  onChange={(e) => handleChange('amount', parseFloat(e.target.value) || 0)}
                  placeholder="0.00"
                  required
                />
                <Form.Control.Feedback type="invalid">
                  Please enter a valid amount between $0.01 and $1,000,000.
                </Form.Control.Feedback>
                <Form.Text className="text-muted">
                  Minimum: $0.01, Maximum: $1,000,000
                </Form.Text>
              </Form.Group>
            </Col>
          </Row>

          {(formData.type === 'transfer' || formData.type === 'payment') && (
            <Form.Group className="mb-3">
              <Form.Label>
                {formData.type === 'transfer' ? 'Recipient Account Number' : 'Payee Account Number'} *
              </Form.Label>
              <Form.Control
                type="text"
                value={formData.toAccountNumber || ''}
                onChange={(e) => handleChange('toAccountNumber', e.target.value)}
                placeholder={formData.type === 'transfer' ? 'Enter recipient account number' : 'Enter payee account number'}
                pattern="ACC[0-9]+[A-Z0-9]+"
                required
              />
              <Form.Control.Feedback type="invalid">
                Please enter a valid account number (e.g., ACC1234567890ABCD).
              </Form.Control.Feedback>
              <Form.Text className="text-muted">
                Account number format: ACC followed by numbers and letters.
              </Form.Text>
            </Form.Group>
          )}

          <Form.Group className="mb-3">
            <Form.Label>Description</Form.Label>
            <Form.Control
              as="textarea"
              rows={3}
              value={formData.description || ''}
              onChange={(e) => handleChange('description', e.target.value)}
              placeholder="Optional description or memo for this transaction"
              maxLength={255}
            />
            <Form.Text className="text-muted">
              Optional description (maximum 255 characters)
            </Form.Text>
          </Form.Group>

          <Form.Group className="mb-3">
            <Form.Label>Authentication Method</Form.Label>
            <Form.Select
              value={formData.authenticationMethod}
              onChange={(e) => handleChange('authenticationMethod', e.target.value as 'password' | 'mfa' | 'biometric')}
            >
              <option value="mfa">Multi-Factor Authentication (Recommended)</option>
              <option value="password">Password Only</option>
              <option value="biometric">Biometric Authentication</option>
            </Form.Select>
            <Form.Text className="text-muted">
              Choose how you want to authenticate this transaction
            </Form.Text>
          </Form.Group>

          <Alert variant="info" className="mb-0">
            <div className="d-flex">
              <i className="fas fa-info-circle me-2 mt-1"></i>
              <div>
                <strong>Security Notice:</strong>
                <ul className="mb-0 mt-1">
                  <li>This transaction will require additional authentication</li>
                  <li>All transactions are monitored for security</li>
                  <li>You will receive a confirmation once processed</li>
                  {formData.amount > 10000 && (
                    <li className="text-warning">
                      <strong>Large Transaction:</strong> Amounts over $10,000 may require additional verification
                    </li>
                  )}
                </ul>
              </div>
            </div>
          </Alert>
        </Modal.Body>

        <Modal.Footer>
          <Button variant="secondary" onClick={handleClose} disabled={loading}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={loading}>
            {loading ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" />
                Processing...
              </>
            ) : (
              <>
                <i className="fas fa-check me-2"></i>
                Create Transaction
              </>
            )}
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
};

export default TransactionForm;
