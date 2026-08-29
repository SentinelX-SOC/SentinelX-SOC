import { resolveWebSocketUrl } from './client';
import type { WebSocketEvent } from '../types/api';

export class SocWebSocket {
  private socket: WebSocket | null = null;
  private onMessageHandler: ((event: WebSocketEvent) => void) | null = null;
  private reconnectTimer: number | null = null;
  private reconnectDelay = 1000;
  private url: string;
  private isConnecting = false;
  private shouldReconnect = true;

  constructor(url = resolveWebSocketUrl()) {
    this.url = url;
  }

  connect(onMessage: (event: WebSocketEvent) => void): void {
    this.onMessageHandler = onMessage;
    this.shouldReconnect = true;

    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.isConnecting) {
      return;
    }

    this.isConnecting = true;
    this.socket = new WebSocket(this.url);

    this.socket.onopen = () => {
      this.isConnecting = false;
      this.reconnectDelay = 1000;
      this.onMessageHandler?.({ type: 'telemetry', event: 'connected' } as WebSocketEvent);
    };

    this.socket.onmessage = (message) => {
      try {
        const raw = JSON.parse(message.data) as WebSocketEvent;
        this.onMessageHandler?.(raw);
      } catch {
        this.onMessageHandler?.({ type: 'telemetry', payload: undefined } as WebSocketEvent);
      }
    };

    this.socket.onerror = () => {
      this.onMessageHandler?.({ type: 'telemetry', event: 'error' } as WebSocketEvent);
    };

    this.socket.onclose = () => {
      this.isConnecting = false;
      this.onMessageHandler?.({ type: 'telemetry', event: 'disconnected' } as WebSocketEvent);

      if (!this.shouldReconnect) {
        this.socket = null;
        return;
      }

      if (this.reconnectTimer !== null) {
        return;
      }

      this.reconnectTimer = window.setTimeout(() => {
        this.reconnectTimer = null;
        this.connect(this.onMessageHandler ?? (() => undefined));
      }, this.reconnectDelay);
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, 10000);
    };
  }

  disconnect(): void {
    this.shouldReconnect = false;
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }
}
