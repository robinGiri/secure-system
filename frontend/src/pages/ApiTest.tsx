import React, { useState } from 'react';
import apiService from '../services/api';

const ApiTest: React.FC = () => {
  const [status, setStatus] = useState<string>('Ready');
  const [result, setResult] = useState<string>('');
  
  const testLogin = async () => {
    setStatus('Testing login...');
    try {
      // Test connectivity first
      const isConnected = await apiService.testConnection();
      if (!isConnected) {
        setResult('Connection test failed. Server may not be reachable.');
        setStatus('Failed');
        return;
      }
      
      // Try login with test credentials
      const response = await apiService.login({
        username: 'testuser',
        password: 'Test123!'
      });
      
      setResult(JSON.stringify(response, null, 2));
      setStatus('Success');
    } catch (error) {
      console.error('Test login error:', error);
      setResult(`Error: ${error instanceof Error ? error.message : String(error)}`);
      setStatus('Failed');
    }
  };
  
  return (
    <div style={{ padding: '20px' }}>
      <h2>API Connection Test</h2>
      <div>
        <button 
          onClick={testLogin}
          disabled={status === 'Testing login...'}
          style={{
            padding: '10px 20px',
            background: '#4285f4',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Test Login API
        </button>
        
        <p>Status: <strong>{status}</strong></p>
        
        {result && (
          <div>
            <h3>Result:</h3>
            <pre style={{ 
              background: '#f5f5f5', 
              padding: '15px', 
              borderRadius: '4px',
              overflow: 'auto',
              maxHeight: '400px'
            }}>
              {result}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default ApiTest;
