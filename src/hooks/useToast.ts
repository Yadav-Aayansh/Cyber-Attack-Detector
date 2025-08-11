import { useState, useCallback } from 'react';
import { Toast } from '../types';

export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [timeouts, setTimeouts] = useState<Map<number, NodeJS.Timeout>>(new Map());
  const [toastIdCounter, setToastIdCounter] = useState(0);

  const addToast = useCallback((message: string, type: Toast['type'] = 'info') => {
    // Generate truly unique ID by combining timestamp with counter
    const id = Date.now() + toastIdCounter;
    setToastIdCounter(prev => prev + 1);
    
    const newToast: Toast = { id, message, type };
    
    setToasts(prev => [...prev, newToast]);
    
    // Auto-remove toast after 5 seconds
    const timeoutId = setTimeout(() => {
      setToasts(prev => prev.filter(toast => toast.id !== id));
      setTimeouts(prev => {
        const newTimeouts = new Map(prev);
        newTimeouts.delete(id);
        return newTimeouts;
      });
    }, 5000);
    
    setTimeouts(prev => new Map(prev).set(id, timeoutId));
    
    return id;
  }, [toastIdCounter]);

  const removeToast = useCallback((id: number) => {
    // Clear the timeout if it exists
    setTimeouts(prev => {
      const timeoutId = prev.get(id);
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      const newTimeouts = new Map(prev);
      newTimeouts.delete(id);
      return newTimeouts;
    });
    
    setToasts(prev => prev.filter(toast => toast.id !== id));
  }, []);

  const clearAllToasts = useCallback(() => {
    // Clear all timeouts
    setTimeouts(prev => {
      prev.forEach(timeoutId => clearTimeout(timeoutId));
      return new Map();
    });
    
    setToasts([]);
    setToastIdCounter(0); // Reset counter when clearing all toasts
  }, []);

  return {
    toasts,
    addToast,
    removeToast,
    clearAllToasts,
  };
}
