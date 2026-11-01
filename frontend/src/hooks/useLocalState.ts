import { useState } from 'react';

// Review data stays on this browser; storage may be unavailable in private sessions.
export function useLocalState<T>(key: string, initial: T) {
  const [value, update] = useState<T>(() => {
    try { const saved = localStorage.getItem(key); return saved ? JSON.parse(saved) as T : initial; }
    catch { return initial; }
  });
  const [error, setError] = useState('');
  function setValue(next: T) {
    update(next);
    try { localStorage.setItem(key, JSON.stringify(next)); setError(''); }
    catch { setError('Browser storage unavailable. Changes last only until this page closes.'); }
  }
  return [value, setValue, error] as const;
}
