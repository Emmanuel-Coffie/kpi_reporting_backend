// src/Login.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  Container,
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Alert,
  Avatar,
  createTheme,
  ThemeProvider,
} from '@mui/material';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';

// Define your custom theme
const theme = createTheme({
  palette: {
    primary: {
      main: '#090446',
    },
    background: {
      default: '#ffffff',
    },
  },
  typography: {
    fontFamily: 'Roboto, sans-serif',
  },
});

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard');
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const user = await login({ username, password });
      if (user?.is_superuser) {
        navigate('/admin/dashboard');
      } else {
        navigate('/dashboard');
      }
    } catch (err) {
      setError('Invalid credentials');
    }
  };

  return (
    <ThemeProvider theme={theme}>
      <Container maxWidth="sm">
        <Box
          sx={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            bgcolor: 'background.default',
          }}
        >
          <Card
            sx={{
              p: 4,
              width: '100%',
              maxWidth: 400,
              boxShadow: 6,
              borderRadius: 3,
              bgcolor: '#fff',
            }}
          >
            <CardContent>
              {/* 🔖 Logo Placeholder */}
              <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
                <img
                  src="/LOGOECG.png" // replace with your actual logo path
                  alt="Logo"
                  style={{ width: 80, height: 80 }}
                />
              </Box>

              {/* <Box sx={{ display: 'flex', justifyContent: 'center', mb:1 }}>
                <Avatar sx={{ bgcolor: 'primary.main' }}>
                  <LockOutlinedIcon />
                </Avatar>
              </Box> */}

              <Typography
                variant="h5"
                align="center"
                gutterBottom
                sx={{ fontWeight: 600, color: 'primary.main' }}
              >
                KPI Reporting System
              </Typography>

              {error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  {error}
                </Alert>
              )}

              <Box component="form" onSubmit={handleSubmit} noValidate>
                <TextField
                  margin="normal"
                  required
                  fullWidth
                  label="Username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoFocus
                />
                <TextField
                  margin="normal"
                  required
                  fullWidth
                  label="Password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  size="large"
                  sx={{
                    mt: 3,
                    borderRadius: 2,
                    textTransform: 'none',
                    fontWeight: 'bold',
                  }}
                >
                  Login
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Box>
      </Container>
    </ThemeProvider>
  );
};

export default Login;
