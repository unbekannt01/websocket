/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-floating-promises */
import {
  ConnectedSocket,
  MessageBody,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

interface Room {
  id: string;
  name: string;
  passwordHash: string;
  inviteToken: string;
  creator: string;
  members: Set<string>;
  createdAt: Date;
  messageCount: number;
}

interface AuthenticatedUser {
  id: string;
  username?: string;
  currentRoom?: string;
  sessionToken: string;
  joinedAt: Date;
  lastActivity: Date;
  messageCount: number;
}

interface RateLimitInfo {
  count: number;
  resetTime: number;
  blocked: boolean;
}

@WebSocketGateway({
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com']
      : '*',
    methods: ['GET', 'POST'],
    credentials: true,
  },
})
export class GatewayService {
  @WebSocketServer()
  server: Server;

  private rooms: Map<string, Room> = new Map();
  private users: Map<string, AuthenticatedUser> = new Map();
  private rateLimiter: Map<string, RateLimitInfo> = new Map();
  
  // Rate limiting configurations
  private readonly rateLimits = {
    'create-room': { maxRequests: 3, windowMs: 300000 }, // 3 rooms per 5 minutes
    'join-room': { maxRequests: 10, windowMs: 60000 },   // 10 joins per minute
    'room-message': { maxRequests: 30, windowMs: 60000 }, // 30 messages per minute
    'connection': { maxRequests: 5, windowMs: 60000 },   // 5 connections per minute per IP
  };

  handleConnection(client: Socket) {
    const clientIp = client.handshake.address || client.id;
    
    // Check connection rate limit
    if (!this.checkRateLimit(clientIp, 'connection')) {
      this.logSecurity('CONNECTION_RATE_LIMITED', client.id, { ip: clientIp });
      client.disconnect(true);
      return;
    }

    console.log('User Connected:', client.id);
    this.logSecurity('USER_CONNECTED', client.id);

    // Initialize authenticated user with session token
    const sessionToken = this.generateSessionToken();
    this.users.set(client.id, {
      id: client.id,
      sessionToken,
      joinedAt: new Date(),
      lastActivity: new Date(),
      messageCount: 0,
    });

    // Send session info to client
    client.emit('session-initialized', { sessionToken });

    // Set up session validation interval
    const sessionInterval = setInterval(() => {
      if (!this.validateAndRefreshSession(client.id)) {
        this.logSecurity('SESSION_EXPIRED', client.id);
        client.disconnect(true);
        clearInterval(sessionInterval);
      }
    }, 300000); // Check every 5 minutes

    // Clean up on disconnect
    client.on('disconnect', () => {
      clearInterval(sessionInterval);
    });
  }

  handleDisconnect(client: Socket) {
    console.log('User Disconnected:', client.id);
    this.logSecurity('USER_DISCONNECTED', client.id);

    const user = this.users.get(client.id);
    if (user && user.currentRoom) {
      this.leaveRoom(client, user.currentRoom);
    }

    this.users.delete(client.id);
    this.cleanupRateLimiter(client.id);
  }

  @SubscribeMessage('create-room')
  async handleCreateRoom(
    @MessageBody() data: { roomName: string; password: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      // Rate limiting check
      if (!this.checkRateLimit(client.id, 'create-room')) {
        client.emit('room-error', { message: 'Too many room creation attempts. Please wait.' });
        this.logSecurity('CREATE_ROOM_RATE_LIMITED', client.id);
        return;
      }

      // Session validation
      if (!this.validateAndRefreshSession(client.id)) {
        client.emit('room-error', { message: 'Invalid session. Please refresh.' });
        return;
      }

      const { roomName, password } = data;

      // Enhanced input validation
      const validationError = this.validateRoomInput(roomName, password);
      if (validationError) {
        client.emit('room-error', { message: validationError });
        this.logSecurity('INVALID_ROOM_INPUT', client.id, { error: validationError });
        return;
      }

      // Generate secure identifiers
      const roomId = this.generateRoomId();
      const inviteToken = this.generateInviteToken();
      const passwordHash = await this.hashPassword(password);

      // Create room with enhanced security
      const room: Room = {
        id: roomId,
        name: this.sanitizeInput(roomName),
        passwordHash,
        inviteToken,
        creator: client.id,
        members: new Set([client.id]),
        createdAt: new Date(),
        messageCount: 0,
      };

      this.rooms.set(roomId, room);

      // Update user
      const user = this.users.get(client.id);
      if (user) {
        user.currentRoom = roomId;
      }

      // Join socket room
      client.join(roomId);

      console.log(`Room created: ${roomId} by ${client.id}`);
      this.logSecurity('ROOM_CREATED', client.id, { roomId, roomName });

      client.emit('room-created', {
        roomId,
        roomName: room.name,
        inviteToken,
        message: 'Room created successfully',
      });

    } catch (error) {
      console.error('Error creating room:', error);
      this.logSecurity('CREATE_ROOM_ERROR', client.id, { error: error.message });
      client.emit('room-error', { message: 'Failed to create room' });
    }
  }

  @SubscribeMessage('join-room')
  async handleJoinRoom(
    @MessageBody() data: { roomId?: string; password?: string; inviteToken?: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      // Rate limiting check
      if (!this.checkRateLimit(client.id, 'join-room')) {
        client.emit('room-error', { message: 'Too many join attempts. Please wait.' });
        this.logSecurity('JOIN_ROOM_RATE_LIMITED', client.id);
        return;
      }

      // Session validation
      if (!this.validateAndRefreshSession(client.id)) {
        client.emit('room-error', { message: 'Invalid session. Please refresh.' });
        return;
      }

      const { roomId, password, inviteToken } = data;

      // Validate input
      if (!roomId || (!password && !inviteToken)) {
        client.emit('room-error', { message: 'Room ID and password or invite token are required' });
        return;
      }

      // Sanitize input
      const sanitizedRoomId = this.sanitizeInput(roomId);

      // Check if room exists
      const room = this.rooms.get(sanitizedRoomId);
      if (!room) {
        client.emit('room-error', { message: 'Room not found' });
        this.logSecurity('ROOM_NOT_FOUND', client.id, { roomId: sanitizedRoomId });
        return;
      }

      // Verify access (password or invite token)
      let accessGranted = false;
      
      if (inviteToken && inviteToken === room.inviteToken) {
        accessGranted = true;
      } else if (password && await this.verifyPassword(password, room.passwordHash)) {
        accessGranted = true;
      }

      if (!accessGranted) {
        client.emit('room-error', { message: 'Invalid credentials' });
        this.logSecurity('INVALID_ROOM_CREDENTIALS', client.id, { roomId: sanitizedRoomId });
        return;
      }

      // Check room member limit (optional security measure)
      if (room.members.size >= 50) {
        client.emit('room-error', { message: 'Room is full' });
        return;
      }

      // Leave current room if any
      const user = this.users.get(client.id);
      if (user && user.currentRoom) {
        this.leaveRoom(client, user.currentRoom);
      }

      // Join new room
      room.members.add(client.id);
      if (user) {
        user.currentRoom = sanitizedRoomId;
      }

      client.join(sanitizedRoomId);

      console.log(`User ${client.id} joined room: ${sanitizedRoomId}`);
      this.logSecurity('ROOM_JOINED', client.id, { roomId: sanitizedRoomId });

      // Notify user
      client.emit('room-joined', {
        roomId: sanitizedRoomId,
        roomName: room.name,
        inviteToken: client.id === room.creator ? room.inviteToken : undefined,
        message: 'Successfully joined room',
      });

      // Notify other room members
      client.to(sanitizedRoomId).emit('user-joined', {
        message: `A user joined the room`,
        memberCount: room.members.size,
      });

    } catch (error) {
      console.error('Error joining room:', error);
      this.logSecurity('JOIN_ROOM_ERROR', client.id, { error: error.message });
      client.emit('room-error', { message: 'Failed to join room' });
    }
  }

  @SubscribeMessage('leave-room')
  handleLeaveRoom(
    @MessageBody() data: { roomId: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      if (!this.validateAndRefreshSession(client.id)) {
        return;
      }

      const { roomId } = data;
      const sanitizedRoomId = this.sanitizeInput(roomId);
      this.leaveRoom(client, sanitizedRoomId);
    } catch (error) {
      console.error('Error leaving room:', error);
      this.logSecurity('LEAVE_ROOM_ERROR', client.id, { error: error.message });
    }
  }

  @SubscribeMessage('room-message')
  async handleRoomMessage(
    @MessageBody() data: { roomId: string; username: string; text: string; timestamp: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      // Rate limiting check
      if (!this.checkRateLimit(client.id, 'room-message')) {
        client.emit('room-error', { message: 'Sending messages too quickly. Please slow down.' });
        return;
      }

      // Session validation
      if (!this.validateAndRefreshSession(client.id)) {
        client.emit('room-error', { message: 'Invalid session. Please refresh.' });
        return;
      }

      const { roomId, username, text, timestamp } = data;

      // Enhanced input validation
      if (!roomId || !username || !text) {
        return;
      }

      const sanitizedRoomId = this.sanitizeInput(roomId);
      const sanitizedUsername = this.sanitizeInput(username, 20);
      const sanitizedText = this.sanitizeInput(text, 1000);

      // Additional message validation
      if (sanitizedText.length < 1 || sanitizedText.length > 1000) {
        client.emit('room-error', { message: 'Message length must be between 1 and 1000 characters' });
        return;
      }

      // Check for suspicious content (basic)
      if (this.containsSuspiciousContent(sanitizedText)) {
        client.emit('room-error', { message: 'Message contains inappropriate content' });
        this.logSecurity('SUSPICIOUS_MESSAGE_BLOCKED', client.id, { text: sanitizedText });
        return;
      }

      // Check if room exists
      const room = this.rooms.get(sanitizedRoomId);
      if (!room) {
        client.emit('room-error', { message: 'Room not found' });
        return;
      }

      // Check if user is member of room
      if (!room.members.has(client.id)) {
        client.emit('room-error', { message: 'You are not a member of this room' });
        this.logSecurity('UNAUTHORIZED_MESSAGE_ATTEMPT', client.id, { roomId: sanitizedRoomId });
        return;
      }

      // Update user activity and stats
      const user = this.users.get(client.id);
      if (user) {
        user.username = sanitizedUsername;
        user.messageCount++;
        
        // Detect spam behavior
        if (user.messageCount > 100) {
          const timeDiff = new Date().getTime() - user.joinedAt.getTime();
          if (timeDiff < 600000 && user.messageCount / (timeDiff / 60000) > 20) { // More than 20 messages per minute average
            this.logSecurity('POTENTIAL_SPAM_DETECTED', client.id, { 
              messageCount: user.messageCount, 
              duration: timeDiff 
            });
          }
        }
      }

      room.messageCount++;

      console.log(`Message in room ${sanitizedRoomId} from ${sanitizedUsername}: ${sanitizedText.substring(0, 50)}...`);

      // Broadcast message to all room members except sender
      client.to(sanitizedRoomId).emit('room-message', {
        roomId: sanitizedRoomId,
        username: sanitizedUsername,
        text: sanitizedText,
        timestamp,
        messageId: this.generateMessageId(),
      });

    } catch (error) {
      console.error('Error handling room message:', error);
      this.logSecurity('MESSAGE_ERROR', client.id, { error: error.message });
    }
  }

  @SubscribeMessage('get-room-info')
  handleGetRoomInfo(
    @MessageBody() data: { roomId: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      if (!this.validateAndRefreshSession(client.id)) {
        return;
      }

      const { roomId } = data;
      const sanitizedRoomId = this.sanitizeInput(roomId);
      const room = this.rooms.get(sanitizedRoomId);

      if (room && room.members.has(client.id)) {
        client.emit('room-info', {
          roomId: room.id,
          roomName: room.name,
          memberCount: room.members.size,
          messageCount: room.messageCount,
          createdAt: room.createdAt,
          isCreator: room.creator === client.id,
        });
      }
    } catch (error) {
      console.error('Error getting room info:', error);
    }
  }

  // Security helper methods
  private async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }

  private async verifyPassword(password: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(password, hash);
  }

  private generateSessionToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private generateInviteToken(): string {
    return crypto.randomBytes(24).toString('hex');
  }

  private generateMessageId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  private validateAndRefreshSession(clientId: string): boolean {
    const user = this.users.get(clientId);
    if (!user || !user.sessionToken) return false;

    // Session expires after 4 hours of inactivity
    const sessionTimeout = 4 * 60 * 60 * 1000;
    const now = new Date();
    
    if (now.getTime() - user.lastActivity.getTime() > sessionTimeout) {
      return false;
    }

    // Refresh activity timestamp
    user.lastActivity = now;
    return true;
  }

  private checkRateLimit(identifier: string, action: string): boolean {
    const key = `${identifier}:${action}`;
    const now = Date.now();
    const limit = this.rateLimiter.get(key);
    const config = this.rateLimits[action];

    if (!config) return true; // No rate limit configured

    if (!limit || now > limit.resetTime) {
      this.rateLimiter.set(key, { 
        count: 1, 
        resetTime: now + config.windowMs,
        blocked: false 
      });
      return true;
    }

    if (limit.blocked) {
      return false;
    }

    if (limit.count >= config.maxRequests) {
      limit.blocked = true;
      this.logSecurity('RATE_LIMIT_EXCEEDED', identifier, { action, count: limit.count });
      return false;
    }

    limit.count++;
    return true;
  }

  private cleanupRateLimiter(clientId: string) {
    const keysToDelete: string[] = [];
    for (const [key] of this.rateLimiter) {
      if (key.startsWith(clientId + ':')) {
        keysToDelete.push(key);
      }
    }
    keysToDelete.forEach(key => this.rateLimiter.delete(key));
  }

  private validateRoomInput(roomName: string, password: string): string | null {
    if (!roomName || !password) {
      return 'Room name and password are required';
    }

    if (typeof roomName !== 'string' || typeof password !== 'string') {
      return 'Invalid input format';
    }

    if (roomName.length < 3 || roomName.length > 30) {
      return 'Room name must be between 3 and 30 characters';
    }

    if (password.length < 8 || password.length > 50) {
      return 'Password must be between 8 and 50 characters';
    }

    // Check for valid characters in room name
    if (!/^[a-zA-Z0-9\s\-_\.]+$/.test(roomName)) {
      return 'Room name contains invalid characters';
    }

    // Password strength check
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      return 'Password must contain at least one uppercase letter, one lowercase letter, and one number';
    }

    return null;
  }

  private sanitizeInput(input: string, maxLength: number = 100): string {
    if (!input || typeof input !== 'string') return '';
    
    return input
      .replace(/[<>\"'&]/g, '') // Remove potentially dangerous characters
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim()
      .substring(0, maxLength);
  }

  private containsSuspiciousContent(text: string): boolean {
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /onload=/i,
      /onerror=/i,
      /eval\(/i,
      /document\.cookie/i,
      /localStorage/i,
      /sessionStorage/i,
    ];

    return suspiciousPatterns.some(pattern => pattern.test(text));
  }

  private leaveRoom(client: Socket, roomId: string) {
    const room = this.rooms.get(roomId);
    if (room) {
      room.members.delete(client.id);
      client.leave(roomId);

      // Update user
      const user = this.users.get(client.id);
      if (user) {
        user.currentRoom = undefined;
      }

      console.log(`User ${client.id} left room: ${roomId}`);
      this.logSecurity('USER_LEFT_ROOM', client.id, { roomId });

      // Notify other room members
      if (room.members.size > 0) {
        client.to(roomId).emit('user-left', {
          message: `A user left the room`,
          memberCount: room.members.size,
        });
      }

      // Clean up empty rooms
      if (room.members.size === 0) {
        setTimeout(() => {
          const currentRoom = this.rooms.get(roomId);
          if (currentRoom && currentRoom.members.size === 0) {
            this.rooms.delete(roomId);
            console.log(`Cleaned up empty room: ${roomId}`);
            this.logSecurity('ROOM_CLEANED_UP', 'system', { roomId });
          }
        }, 300000); // 5 minutes
      }
    }
  }

  private generateRoomId(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    // Ensure uniqueness
    if (this.rooms.has(result)) {
      return this.generateRoomId();
    }

    return result;
  }

  private logSecurity(event: string, clientId: string, details?: any) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      clientId,
      ...details,
    };
    
    console.log(`[SECURITY] ${JSON.stringify(logEntry)}`);
    
    // In production, you might want to send this to a logging service
    // or store in a secure log file
  }
}