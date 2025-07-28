import React, { useState, useEffect } from 'react';
import { apiService } from '../services/api';

const DebugConnection: React.FC = () => {
  const [connectionStatus, setConnectionStatus] = useState<string>('Testing...');
  const [testResults, setTestResults] = useState<any[]>([]);

  const runConnectionTests = async () => {
    const results: any[] = [];
    const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000';

    // Test 1: Basic connectivity
    try {
      const isConnected = await apiService.testConnection();
      results.push({
        test: 'Basic Connectivity',
        status: isConnected ? 'PASS' : 'FAIL',
        details: `Connection to backend: ${isConnected ? 'Success' : 'Failed'}`
      });
    } catch (error) {
      results.push({
        test: 'Basic Connectivity',
        status: 'ERROR',
        details: `Error: ${error}`
      });
    }

    // Test 2: Environment variables
    results.push({
      test: 'Environment Variables',
      status: 'INFO',
      details: {
        REACT_APP_API_URL: process.env.REACT_APP_API_URL || 'Not set',
        API_BASE_URL_CALCULATED: API_BASE_URL,
        Current_Origin: window.location.origin,
        User_Agent: navigator.userAgent,
        Protocol: window.location.protocol
      }
    });

    // Test 3: Simple fetch test with detailed error handling
    try {
      console.log('Starting direct fetch test to:', `${API_BASE_URL}/api/auth/login`);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
      
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Origin': window.location.origin
        },
        body: JSON.stringify({
          email: 'test@test.com',
          password: 'test'
        }),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      const responseText = await response.text();
      
      results.push({
        test: 'Direct Fetch Test',
        status: response.ok ? 'PASS' : 'RESPONSE_ERROR',
        details: {
          url: `${API_BASE_URL}/api/auth/login`,
          status: response.status,
          statusText: response.statusText,
          headers: Array.from(response.headers.entries()).reduce((acc, [key, value]) => ({ ...acc, [key]: value }), {}),
          body: responseText.substring(0, 500) + (responseText.length > 500 ? '...' : '')
        }
      });
    } catch (error) {
      results.push({
        test: 'Direct Fetch Test',
        status: 'NETWORK_ERROR',
        details: {
          url: `${API_BASE_URL}/api/auth/login`,
          error: `${error}`,
          name: error instanceof Error ? error.name : 'Unknown',
          message: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack?.substring(0, 500) : 'No stack trace'
        }
      });
    }

    // Test 4: Browser security checks
    try {
      results.push({
        test: 'Browser Security Info',
        status: 'INFO',
        details: {
          isSecureContext: window.isSecureContext,
          location: window.location.href,
          corsMode: 'cors',
          fetchSupport: typeof fetch !== 'undefined',
          promiseSupport: typeof Promise !== 'undefined'
        }
      });
    } catch (error) {
      results.push({
        test: 'Browser Security Info',
        status: 'ERROR',
        details: `Error getting browser info: ${error}`
      });
    }

    // Test 5: Network connectivity test
    try {
      await fetch(`${API_BASE_URL}/`, {
        method: 'HEAD',
        mode: 'no-cors'
      });
      
      results.push({
        test: 'No-CORS Connection Test',
        status: 'PASS',
        details: `Basic network connectivity confirmed to ${API_BASE_URL}`
      });
    } catch (error) {
      results.push({
        test: 'No-CORS Connection Test',
        status: 'FAIL',
        details: `Network connectivity issue to ${API_BASE_URL}: ${error}`
      });
    }

    setTestResults(results);
    setConnectionStatus('Tests completed');
  };

  useEffect(() => {
    runConnectionTests();
  }, []);

  return (
    <div style={{ padding: '20px', fontFamily: 'monospace' }}>
      <h2>API Connection Debug</h2>
      <p><strong>Status:</strong> {connectionStatus}</p>
      
      <div style={{ marginTop: '20px' }}>
        <h3>Test Results:</h3>
        {testResults.map((result, index) => (
          <div key={index} style={{ 
            margin: '10px 0', 
            padding: '10px', 
            border: '1px solid #ccc',
            backgroundColor: result.status === 'PASS' ? '#d4edda' : 
                             result.status === 'FAIL' || result.status === 'ERROR' || result.status === 'NETWORK_ERROR' ? '#f8d7da' : '#d1ecf1'
          }}>
            <h4>{result.test}: <span style={{ color: result.status === 'PASS' ? 'green' : result.status === 'INFO' ? 'blue' : 'red' }}>
              {result.status}
            </span></h4>
            <pre style={{ whiteSpace: 'pre-wrap', fontSize: '12px' }}>
              {typeof result.details === 'object' ? JSON.stringify(result.details, null, 2) : result.details}
            </pre>
          </div>
        ))}
      </div>

      <div style={{ marginTop: '20px' }}>
        <button onClick={runConnectionTests} style={{ padding: '10px 20px' }}>
          Re-run Tests
        </button>
      </div>
    </div>
  );
};

export default DebugConnection;
