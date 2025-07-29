import React, { useState, useEffect } from 'react';
import { Form, Card } from 'react-bootstrap';

interface SimpleCaptchaProps {
  onVerify: (token: string) => void;
  required?: boolean;
  className?: string;
}

const SimpleCaptcha: React.FC<SimpleCaptchaProps> = ({ 
  onVerify, 
  required = false,
  className = '' 
}) => {
  const [question, setQuestion] = useState('');
  const [correctAnswer, setCorrectAnswer] = useState(0);
  const [userAnswer, setUserAnswer] = useState('');
  const [isVerified, setIsVerified] = useState(!required);

  // Generate a simple math question
  const generateQuestion = () => {
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const operations = ['+', '-', '*'];
    const operation = operations[Math.floor(Math.random() * operations.length)];
    
    let result: number;
    let questionText: string;
    
    switch (operation) {
      case '+':
        result = num1 + num2;
        questionText = `${num1} + ${num2}`;
        break;
      case '-':
        // Ensure positive result
        const larger = Math.max(num1, num2);
        const smaller = Math.min(num1, num2);
        result = larger - smaller;
        questionText = `${larger} - ${smaller}`;
        break;
      case '*':
        // Use smaller numbers for multiplication
        const small1 = Math.floor(Math.random() * 5) + 1;
        const small2 = Math.floor(Math.random() * 5) + 1;
        result = small1 * small2;
        questionText = `${small1} × ${small2}`;
        break;
      default:
        result = num1 + num2;
        questionText = `${num1} + ${num2}`;
    }
    
    setQuestion(questionText);
    setCorrectAnswer(result);
    setUserAnswer('');
    setIsVerified(false);
  };

  useEffect(() => {
    if (required) {
      generateQuestion();
    }
  }, [required]);

  const handleAnswerChange = (value: string) => {
    setUserAnswer(value);
    
    const numValue = parseInt(value);
    if (!isNaN(numValue) && numValue === correctAnswer) {
      setIsVerified(true);
      // Generate a simple token (in production, this would be from a proper CAPTCHA service)
      const token = `captcha_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      onVerify(token);
    } else {
      setIsVerified(false);
      onVerify('');
    }
  };

  const handleRefresh = () => {
    generateQuestion();
  };

  if (!required) {
    return null;
  }

  return (
    <Card className={`mb-3 ${className}`} style={{ backgroundColor: '#f8f9fa' }}>
      <Card.Body className="py-3">
        <div className="d-flex align-items-center justify-content-between">
          <div className="d-flex align-items-center">
            <i className="fas fa-shield-alt me-2 text-primary"></i>
            <div>
              <Form.Label className="mb-1 fw-semibold">Security Verification</Form.Label>
              <div className="d-flex align-items-center">
                <span className="me-2">What is</span>
                <strong className="me-2 text-primary">{question}</strong>
                <span className="me-2">=</span>
                <Form.Control
                  type="number"
                  value={userAnswer}
                  onChange={(e) => handleAnswerChange(e.target.value)}
                  placeholder="?"
                  style={{ width: '80px' }}
                  className="text-center"
                />
              </div>
            </div>
          </div>
          <div className="d-flex align-items-center">
            {isVerified ? (
              <i className="fas fa-check-circle text-success fs-5"></i>
            ) : (
              <button
                type="button"
                className="btn btn-outline-secondary btn-sm"
                onClick={handleRefresh}
                title="Get new question"
              >
                <i className="fas fa-sync-alt"></i>
              </button>
            )}
          </div>
        </div>
        
        {userAnswer && !isVerified && (
          <div className="mt-2">
            <small className="text-danger">
              <i className="fas fa-exclamation-triangle me-1"></i>
              Incorrect answer. Please try again.
            </small>
          </div>
        )}
        
        {isVerified && (
          <div className="mt-2">
            <small className="text-success">
              <i className="fas fa-check me-1"></i>
              Security verification completed successfully.
            </small>
          </div>
        )}
      </Card.Body>
    </Card>
  );
};

export default SimpleCaptcha;
