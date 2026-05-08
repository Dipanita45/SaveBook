"use client"
import React, { createContext, useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import AuthContext from './authContext';

// Dynamically imported at call time — never runs on the server
let clientCrypto = null;
async function getCrypto() {
  if (!clientCrypto) {
    clientCrypto = await import('@/lib/utils/clientCrypto');
  }
  return clientCrypto;
}

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  // true when user is authenticated but master key was lost due to page refresh
  const [needsRelogin, setNeedsRelogin] = useState(false);
  const masterKeyRef = useRef(null);
  const router = useRouter();

  const clearAuthTokenCookie = useCallback(async () => {
    try {
      await fetch('/api/auth/logout', { method: 'GET', credentials: 'include' });
    } catch {
      // Local auth state is still invalid if the in-memory key is gone.
    }
  }, []);

  const checkUserAuthentication = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/auth/user', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      const data = await response.json();
      if (data.success) {
        if (!masterKeyRef.current) {
          await clearAuthTokenCookie();
          masterKeyRef.current = null;
          setUser(null);
          setIsAuthenticated(false);
          setNeedsRelogin(true);
          return;
        }

        setUser(data.user);
        setIsAuthenticated(true);
        setNeedsRelogin(false);
      } else {
        setIsAuthenticated(false);
        setUser(null);
        masterKeyRef.current = null;
        setNeedsRelogin(false);
      }
    } catch {
      setIsAuthenticated(false);
      setUser(null);
      masterKeyRef.current = null;
      setNeedsRelogin(false);
    } finally {
      setLoading(false);
    }
  }, [clearAuthTokenCookie]);

  useEffect(() => {
    checkUserAuthentication();
  }, [checkUserAuthentication]);

  const login = async (username, password) => {
    try {
      setLoading(true);
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        credentials: 'include',
      });
      const data = await response.json();

      if (data.success) {
        const userId = data.data.user.id;

        if (data.data.encryptedMasterKey) {
          const { decryptMasterKey } = await getCrypto();
          masterKeyRef.current = await decryptMasterKey(data.data.encryptedMasterKey, password, userId);
        } else {
          const { generateMasterKey, encryptMasterKey } = await getCrypto();
          const newMasterKey = await generateMasterKey();
          const encryptedBlob = await encryptMasterKey(newMasterKey, password, userId);
          masterKeyRef.current = newMasterKey;
          await fetch('/api/auth/master-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ encryptedMasterKey: encryptedBlob }),
          });
        }

        setUser(data.data.user);
        setIsAuthenticated(true);
        setNeedsRelogin(false);
        return { success: true, message: data.message, recoveryCodes: data.data?.recoveryCodes || null };
      }
      return { success: false, message: data.message || 'Login failed' };
    } catch {
      return { success: false, message: 'An error occurred during login' };
    } finally {
      setLoading(false);
    }
  };

  const register = async (username, email, password) => {
    try {
      setLoading(true);

      // Step 1: register without a master key first to get the userId
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password }),
        credentials: 'include',
      });
      const data = await response.json();

      if (!data.success) {
        return { success: false, message: data.message || data.error || 'Registration failed' };
      }

      // Step 2: now we have the real userId — generate and wrap master key with correct salt
      const userId = data.userId;
      const { generateMasterKey, encryptMasterKey } = await getCrypto();
      const newMasterKey = await generateMasterKey();
      const encryptedBlob = await encryptMasterKey(newMasterKey, password, userId);

      // Step 3: save the correctly-salted encrypted master key
      await fetch('/api/auth/master-key-register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, encryptedMasterKey: encryptedBlob }),
      });

      return { success: true, message: data.message };
    } catch (err) {
      console.error('Registration error:', err);
      return { success: false, message: err?.message || 'An error occurred during registration' };
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      await clearAuthTokenCookie();
    } finally {
      masterKeyRef.current = null;
      setUser(null);
      setIsAuthenticated(false);
      setNeedsRelogin(false);
      router.push('/');
    }
  };

  const getMasterKey = useCallback(() => masterKeyRef.current, []);

  return (
    <AuthContext.Provider value={{
      user,
      loading,
      isAuthenticated,
      needsRelogin,
      login,
      register,
      logout,
      checkUserAuthentication,
      getMasterKey,
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthProvider;
