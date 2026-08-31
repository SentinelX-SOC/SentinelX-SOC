import { useMemo, useState } from 'react';
import { CircleAlert, LoaderCircle, Shield } from 'lucide-react';
import {
  confirmPasswordReset,
  googleStartUrl,
  login,
  requestPasswordReset,
  signup,
  type AuthenticatedUser,
} from '../api/auth';

type AuthView = 'login' | 'signup' | 'forgot' | 'reset';

const GOOGLE_ERRORS: Record<string, string> = {
  google_unavailable: 'Google sign-in is not configured on this server.',
  google_denied: 'Google sign-in was cancelled.',
  google_invalid_state: 'Google sign-in could not be verified. Please try again.',
  google_missing_code: 'Google sign-in did not complete. Please try again.',
  google_account_disabled: 'This account is disabled.',
  google_failed: 'Google sign-in failed. Please try again.',
};

function takeSearchParam(name: string): string | null {
  const params = new URLSearchParams(window.location.search);
  const value = params.get(name);
  if (value === null) {
    return null;
  }
  params.delete(name);
  const next = params.toString();
  window.history.replaceState(null, '', `${window.location.pathname}${next ? `?${next}` : ''}${window.location.hash}`);
  return value;
}

function AuthBrand() {
  return (
    <div className="auth-brand">
      <div className="brand-mark">OS</div>
      <div>
        <div className="brand-name">Obsidian Sentinel</div>
        <div className="brand-subtitle">SOC Command</div>
      </div>
    </div>
  );
}

function GoogleButton({ disabled }: { disabled: boolean }) {
  return (
    <button
      className="google-btn"
      type="button"
      disabled={disabled}
      onClick={() => {
        window.location.assign(googleStartUrl());
      }}
    >
      <GoogleMark />
      Continue with Google
    </button>
  );
}

function GoogleMark() {
  return (
    <svg className="google-mark" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#4285F4" d="M23.49 12.27c0-.82-.07-1.64-.23-2.43H12v4.6h6.46a5.52 5.52 0 0 1-2.4 3.63v3h3.87c2.26-2.08 3.56-5.15 3.56-8.8z" />
      <path fill="#34A853" d="M12 24c3.24 0 5.97-1.07 7.96-2.93l-3.87-3c-1.08.72-2.47 1.13-4.09 1.13-3.14 0-5.8-2.12-6.75-4.97H1.27v3.09A12 12 0 0 0 12 24z" />
      <path fill="#FBBC05" d="M5.25 14.23A7.2 7.2 0 0 1 4.87 12c0-.78.13-1.53.36-2.23V6.68H1.27A12 12 0 0 0 0 12c0 1.94.46 3.77 1.27 5.32l3.98-3.09z" />
      <path fill="#EA4335" d="M12 4.75c1.76 0 3.35.6 4.6 1.79l3.43-3.43C17.96 1.14 15.23 0 12 0 7.31 0 3.26 2.69 1.27 6.68l3.98 3.09C6.2 6.87 8.86 4.75 12 4.75z" />
    </svg>
  );
}

function AuthNotice({ error, success }: { error: string | null; success: string | null }) {
  if (error) {
    return (
      <div className="notice error" role="alert">
        <CircleAlert size={15} />
        {error}
      </div>
    );
  }
  if (success) {
    return (
      <div className="notice success" role="status">
        {success}
      </div>
    );
  }
  return null;
}

export function AuthGate({ onAuthenticated }: { onAuthenticated: (user: AuthenticatedUser) => void }) {
  const initial = useMemo(() => {
    const resetToken = takeSearchParam('reset_token');
    const authError = takeSearchParam('auth_error');
    return {
      view: (resetToken ? 'reset' : 'login') as AuthView,
      resetToken,
      error: authError ? GOOGLE_ERRORS[authError] ?? 'Sign-in could not be completed.' : null,
    };
  }, []);

  const [view, setView] = useState<AuthView>(initial.view);
  const [error, setError] = useState<string | null>(initial.error);
  const [success, setSuccess] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [resetToken] = useState<string | null>(initial.resetToken);
  const [devResetUrl, setDevResetUrl] = useState<string | null>(null);

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const switchView = (next: AuthView) => {
    setView(next);
    setError(null);
    setSuccess(null);
    setSubmitting(false);
    setPassword('');
    setConfirmPassword('');
    if (next === 'login' || next === 'forgot') {
      setName('');
    }
  };

  const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      onAuthenticated(await login(email, password));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Invalid email or password');
    } finally {
      setSubmitting(false);
    }
  };

  const handleSignup = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      onAuthenticated(await signup({ name, email, password, confirmPassword }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to create account');
    } finally {
      setSubmitting(false);
    }
  };

  const handleForgot = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    setDevResetUrl(null);
    try {
      const result = await requestPasswordReset(email);
      setSuccess(result.message);
      if (result.reset_url) {
        setDevResetUrl(result.reset_url);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to request a reset');
    } finally {
      setSubmitting(false);
    }
  };

  const handleReset = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!resetToken) {
      setError('This reset link is invalid or has expired');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const result = await confirmPasswordReset(resetToken, password, confirmPassword);
      setSuccess(result.message);
      setPassword('');
      setConfirmPassword('');
      setView('login');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to reset password');
    } finally {
      setSubmitting(false);
    }
  };

  const heading = {
    login: { eyebrow: 'Secure access', title: 'Sign in to operations', copy: 'Authenticate to access the live SOC workspace.' },
    signup: { eyebrow: 'Create account', title: 'Join operations', copy: 'Create an Obsidian Sentinel account with email and password.' },
    forgot: { eyebrow: 'Account recovery', title: 'Forgot password', copy: 'Enter your email. If an account exists, a reset link will be issued.' },
    reset: { eyebrow: 'Account recovery', title: 'Set a new password', copy: 'Choose a new password, then return to sign in.' },
  }[view];

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="auth-title">
        <AuthBrand />
        <div className="auth-heading">
          <span className="eyebrow">{heading.eyebrow}</span>
          <h1 id="auth-title">{heading.title}</h1>
          <p>{heading.copy}</p>
        </div>

        {view === 'login' ? (
          <form className="auth-form" onSubmit={(event) => void handleLogin(event)}>
            <label>
              <span>Email</span>
              <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" required />
            </label>
            <label>
              <span>Password</span>
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required />
            </label>
            <AuthNotice error={error} success={success} />
            <button className="action-btn auth-submit" type="submit" disabled={submitting}>
              {submitting ? <LoaderCircle className="spin" size={15} /> : <Shield size={15} />}
              {submitting ? 'Signing in...' : 'Sign in'}
            </button>
            <button className="text-btn auth-inline-link" type="button" onClick={() => switchView('forgot')}>
              Forgot password?
            </button>
            <div className="auth-divider"><span>or</span></div>
            <GoogleButton disabled={submitting} />
            <p className="auth-switch">
              Don&apos;t have an account?{' '}
              <button className="text-btn" type="button" onClick={() => switchView('signup')}>Sign Up</button>
            </p>
          </form>
        ) : null}

        {view === 'signup' ? (
          <form className="auth-form" onSubmit={(event) => void handleSignup(event)}>
            <label>
              <span>Name</span>
              <input value={name} onChange={(event) => setName(event.target.value)} autoComplete="name" required />
            </label>
            <label>
              <span>Email</span>
              <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" required />
            </label>
            <label>
              <span>Password</span>
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" required minLength={8} />
            </label>
            <label>
              <span>Confirm password</span>
              <input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" required minLength={8} />
            </label>
            <p className="auth-hint">Use at least 8 characters. Do not start or end with spaces.</p>
            <AuthNotice error={error} success={success} />
            <button className="action-btn auth-submit" type="submit" disabled={submitting}>
              {submitting ? <LoaderCircle className="spin" size={15} /> : <Shield size={15} />}
              {submitting ? 'Creating account...' : 'Create Account'}
            </button>
            <div className="auth-divider"><span>or</span></div>
            <GoogleButton disabled={submitting} />
            <p className="auth-switch">
              <button className="text-btn" type="button" onClick={() => switchView('login')}>Back to Sign In</button>
            </p>
          </form>
        ) : null}

        {view === 'forgot' ? (
          <form className="auth-form" onSubmit={(event) => void handleForgot(event)}>
            <label>
              <span>Email</span>
              <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" required />
            </label>
            <AuthNotice error={error} success={success} />
            {devResetUrl ? (
              <a className="action-btn auth-submit auth-dev-link" href={devResetUrl}>
                Open local reset page
              </a>
            ) : null}
            <button className="action-btn auth-submit" type="submit" disabled={submitting}>
              {submitting ? <LoaderCircle className="spin" size={15} /> : <Shield size={15} />}
              {submitting ? 'Sending...' : 'Send Reset Link'}
            </button>
            <p className="auth-switch">
              <button className="text-btn" type="button" onClick={() => switchView('login')}>Back to Sign In</button>
            </p>
          </form>
        ) : null}

        {view === 'reset' ? (
          <form className="auth-form" onSubmit={(event) => void handleReset(event)}>
            <label>
              <span>New password</span>
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" required minLength={8} />
            </label>
            <label>
              <span>Confirm password</span>
              <input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" required minLength={8} />
            </label>
            <p className="auth-hint">Use at least 8 characters. Do not start or end with spaces.</p>
            <AuthNotice error={error} success={success} />
            <button className="action-btn auth-submit" type="submit" disabled={submitting || !resetToken}>
              {submitting ? <LoaderCircle className="spin" size={15} /> : <Shield size={15} />}
              {submitting ? 'Updating...' : 'Reset Password'}
            </button>
            <p className="auth-switch">
              <button className="text-btn" type="button" onClick={() => switchView('login')}>Return to Sign In</button>
            </p>
          </form>
        ) : null}

        <div className="auth-footnote">Enterprise multi-user authentication · role-based access control</div>
      </section>
    </main>
  );
}
