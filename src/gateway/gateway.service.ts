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
  memberPublicKeys: Map<string, string>;
}

interface AuthenticatedUser {
  id: string;
  username?: string;
  currentRoom?: string;
  sessionToken: string;
  joinedAt: Date;
  lastActivity: Date;
  messageCount: number;
  publicKey?: string;
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
  
  private readonly rateLimits = {
    'create-room': { maxRequests: 3, windowMs: 300000 },
    'join-room': { maxRequests: 10, windowMs: 60000 },
    'room-message': { maxRequests: 30, windowMs: 60000 },
    'connection': { maxRequests: 5, windowMs: 60000 },
    'register-public-key': { maxRequests: 5, windowMs: 60000 },
  };

  handleConnection(client: Socket) {
    const clientIp = client.handshake.address || client.id;
    
    if (!this.checkRateLimit(clientIp, 'connection')) {
      this.logSecurity('CONNECTION_RATE_LIMITED', client.id, { ip: clientIp });
      client.disconnect(true);
      return;
    }

    const sessionToken = this.generateSessionToken();
    this.users.set(client.id, {
      id: client.id,
      sessionToken,
      joinedAt: new Date(),
      lastActivity: new Date(),
      messageCount: 0,
    });

    client.emit('session-initialized', { sessionToken });

    const sessionInterval = setInterval(() => {
      if (!this.validateAndRefreshSession(client.id)) {
        this.logSecurity('SESSION_EXPIRED', client.id);
        client.disconnect(true);
        clearInterval(sessionInterval);
      }
    }, 300000);

    client.on('disconnect', () => {
      clearInterval(sessionInterval);
    });
  }

  handleDisconnect(client: Socket) {
    this.logSecurity('USER_DISCONNECTED', client.id);

    const user = this.users.get(client.id);
    if (user && user.currentRoom) {
      this.leaveRoom(client, user.currentRoom);
    }

    this.users.delete(client.id);
    this.cleanupRateLimiter(client.id);
  }

  @SubscribeMessage('register-public-key')
  handleRegisterPublicKey(
    @MessageBody() data: { publicKey: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      if (!this.checkRateLimit(client.id, 'register-public-key')) {
        client.emit('key-error', { message: 'Too many key registration attempts' });
        return;
      }

      if (!this.validateAndRefreshSession(client.id)) {
        client.emit('key-error', { message: 'Invalid session' });
        return;
      }

      const { publicKey } = data;

      if (!publicKey || typeof publicKey !== 'string' || publicKey.length < 100 || publicKey.length > 1000) {
        client.emit('key-error', { message: 'Invalid public key format' });
        return;
      }

      const user = this.users.get(client.id);
      if (user) {
        user.publicKey = publicKey;
        this.logSecurity('PUBLIC_KEY_REGISTERED', client.id);
        client.emit('key-registered', { success: true });

        if (user.currentRoom) {
          const room = this.rooms.get(user.currentRoom);
          if (room) {
            room.memberPublicKeys.set(client.id, publicKey);
            client.to(user.currentRoom).emit('member-key-updated', {
              memberId: client.id,
              publicKey: publicKey,
            });
          }
        }
      }
    } catch (error) {
      client.emit('key-error', { message: 'Failed to register public key' });
    }
  }

  @SubscribeMessage('get-room-public-keys')
  handleGetRoomPublicKeys(
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

      if (!room || !room.members.has(client.id)) {
        client.emit('key-error', { message: 'Not authorized' });
        return;
      }

      const publicKeys: { [key: string]: string } = {};
      room.members.forEach((memberId) => {
        const publicKey = room.memberPublicKeys.get(memberId);
        if (publicKey) {
          publicKeys[memberId] = publicKey;
        }
      });

      client.emit('room-public-keys', { publicKeys });
    } catch (error) {
      // Handle error silently
    }
  }

  @SubscribeMessage('create-room')
  async handleCreateRoom(
    @MessageBody() data: { roomName: string; password: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      if (!this.checkRateLimit(client.id, 'create-room')) {
        client.emit('room-error', { message: 'Too many room creation attempts. Please wait.' });
        this.logSecurity('CREATE_ROOM_RATE_LIMITED', client.id);
        return;
      }

      if (!this.validateAndRefreshSession(client.id)) {
        client.emit('room-error', { message: 'Invalid session. Please refresh.' });
        return;
      }

      const { roomName, password } = data;

      const validationError = this.validateRoomInput(roomName, password);
      if (validationError) {
        client.emit('room-error', { message: validationError });
        this.logSecurity('INVALID_ROOM_INPUT', client.id, { error: validationError });
        return;
      }

      const roomId = this.generateRoomId();
      const inviteToken = this.generateInviteToken();
      const passwordHash = await this.hashPassword(password);

      const room: Room = {
        id: roomId,
        name: this.sanitizeInput(roomName),
        passwordHash,
        inviteToken,
        creator: client.id,
        members: new Set([client.id]),
        createdAt: new Date(),
        messageCount: 0,
        memberPublicKeys: new Map(),
      };

      const user = this.users.get(client.id);
      if (user?.publicKey) {
        room.memberPublicKeys.set(client.id, user.publicKey);
      }

      this.rooms.set(roomId, room);

      if (user) {
        user.currentRoom = roomId;
      }

      client.join(roomId);

      this.logSecurity('ROOM_CREATED', client.id, { roomId, roomName });

      client.emit('room-created', {
        roomId,
        roomName: room.name,
        inviteToken,
        message: 'Room created successfully',
        encryptionEnabled: true,
      });

    } catch (error) {
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
      if (!this.checkRateLimit(client.id, 'join-room')) {
        client.emit('room-error', { message: 'Too many join attempts. Please wait.' });
        this.logSecurity('JOIN_ROOM_RATE_LIMITED', client.id);
        return;
      }

      if (!this.validateAndRefreshSession(client.id)) {
        client.emit('room-error', { message: 'Invalid session. Please refresh.' });
        return;
      }

      const { roomId, password, inviteToken } = data;

      if (!roomId || (!password && !inviteToken)) {
        client.emit('room-error', { message: 'Room ID and password or invite token are required' });
        return;
      }

      const sanitizedRoomId = this.sanitizeInput(roomId);
      const room = this.rooms.get(sanitizedRoomId);
      
      if (!room) {
        client.emit('room-error', { message: 'Room not found' });
        this.logSecurity('ROOM_NOT_FOUND', client.id, { roomId: sanitizedRoomId });
        return;
      }

      // Check if user is already in this room
      if (room.members.has(client.id)) {
        const user = this.users.get(client.id);
        if (user && user.currentRoom === sanitizedRoomId) {
          // User is already in the room, just confirm without notifications
          const publicKeys: { [key: string]: string } = {};
          room.memberPublicKeys.forEach((key, memberId) => {
            publicKeys[memberId] = key;
          });

          client.emit('room-joined', {
            roomId: sanitizedRoomId,
            roomName: room.name,
            inviteToken: client.id === room.creator ? room.inviteToken : undefined,
            message: 'Already in room',
            encryptionEnabled: true,
            publicKeys,
          });
          return;
        }
      }

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

      if (room.members.size >= 50) {
        client.emit('room-error', { message: 'Room is full' });
        return;
      }

      const user = this.users.get(client.id);
      if (user && user.currentRoom && user.currentRoom !== sanitizedRoomId) {
        this.leaveRoom(client, user.currentRoom);
      }

      room.members.add(client.id);
      
      if (user?.publicKey) {
        room.memberPublicKeys.set(client.id, user.publicKey);
      }

      if (user) {
        user.currentRoom = sanitizedRoomId;
      }

      client.join(sanitizedRoomId);

      this.logSecurity('ROOM_JOINED', client.id, { roomId: sanitizedRoomId });

      const publicKeys: { [key: string]: string } = {};
      room.memberPublicKeys.forEach((key, memberId) => {
        publicKeys[memberId] = key;
      });

      client.emit('room-joined', {
        roomId: sanitizedRoomId,
        roomName: room.name,
        inviteToken: client.id === room.creator ? room.inviteToken : undefined,
        message: 'Successfully joined room',
        encryptionEnabled: true,
        publicKeys,
      });

      // Only notify others when a NEW user joins
      client.to(sanitizedRoomId).emit('user-joined', {
        message: `A user joined the room`,
        memberCount: room.members.size,
        newMemberId: client.id,
        newMemberPublicKey: user?.publicKey,
      });

    } catch (error) {
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
      this.logSecurity('LEAVE_ROOM_ERROR', client.id, { error: error.message });
    }
  }

  @SubscribeMessage('encrypted-message')
  async handleEncryptedMessage(
    @MessageBody() data: {
      roomId: string;
      username: string;
      encryptedContent: string;
      iv: string;
      timestamp: string;
      signature?: string;
    },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      if (!this.checkRateLimit(client.id, 'room-message')) {
        client.emit('room-error', { message: 'Sending messages too quickly. Please slow down.' });
        return;
      }

      if (!this.validateAndRefreshSession(client.id)) {
        client.emit('room-error', { message: 'Invalid session. Please refresh.' });
        return;
      }

      const { roomId, username, encryptedContent, iv, timestamp, signature } = data;

      if (!roomId || !username || !encryptedContent || !iv) {
        client.emit('room-error', { message: 'Missing required fields' });
        return;
      }

      const sanitizedRoomId = this.sanitizeInput(roomId);
      const sanitizedUsername = this.sanitizeInput(username, 20);

      if (encryptedContent.length > 10000) {
        client.emit('room-error', { message: 'Message too large' });
        return;
      }

      const room = this.rooms.get(sanitizedRoomId);
      if (!room) {
        client.emit('room-error', { message: 'Room not found' });
        return;
      }

      if (!room.members.has(client.id)) {
        client.emit('room-error', { message: 'You are not a member of this room' });
        this.logSecurity('UNAUTHORIZED_MESSAGE_ATTEMPT', client.id, { roomId: sanitizedRoomId });
        return;
      }

      const user = this.users.get(client.id);
      if (user) {
        user.username = sanitizedUsername;
        user.messageCount++;
        
        if (user.messageCount > 100) {
          const timeDiff = new Date().getTime() - user.joinedAt.getTime();
          if (timeDiff < 600000 && user.messageCount / (timeDiff / 60000) > 20) {
            this.logSecurity('POTENTIAL_SPAM_DETECTED', client.id, { 
              messageCount: user.messageCount, 
              duration: timeDiff 
            });
          }
        }
      }

      room.messageCount++;

      this.logSecurity('ENCRYPTED_MESSAGE_SENT', client.id, { roomId: sanitizedRoomId });

      // Relay to all room members INCLUDING sender for confirmation
      this.server.to(sanitizedRoomId).emit('encrypted-message', {
        roomId: sanitizedRoomId,
        username: sanitizedUsername,
        encryptedContent,
        iv,
        timestamp,
        senderId: client.id,
        messageId: this.generateMessageId(),
        signature,
      });

    } catch (error) {
      this.logSecurity('ENCRYPTED_MESSAGE_ERROR', client.id, { error: error.message });
    }
  }

  @SubscribeMessage('room-message')
  async handleRoomMessage(
    @MessageBody() data: { roomId: string; username: string; text: string; timestamp: string },
    @ConnectedSocket() client: Socket,
  ) {
    client.emit('room-warning', { 
      message: 'Unencrypted messages are deprecated. Please use encrypted messaging.' 
    });
    
    client.emit('room-error', { 
      message: 'Please use encrypted messaging for security' 
    });
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
          encryptionEnabled: true,
        });
      }
    } catch (error) {
      // Handle error silently
    }
  }

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

    const sessionTimeout = 4 * 60 * 60 * 1000;
    const now = new Date();
    
    if (now.getTime() - user.lastActivity.getTime() > sessionTimeout) {
      return false;
    }

    user.lastActivity = now;
    return true;
  }

  private checkRateLimit(identifier: string, action: string): boolean {
    const key = `${identifier}:${action}`;
    const now = Date.now();
    const limit = this.rateLimiter.get(key);
    const config = this.rateLimits[action];

    if (!config) return true;

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

    if (!/^[a-zA-Z0-9\s\-_\.]+$/.test(roomName)) {
      return 'Room name contains invalid characters';
    }

    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      return 'Password must contain at least one uppercase letter, one lowercase letter, and one number';
    }

    return null;
  }

  private sanitizeInput(input: string, maxLength: number = 100): string {
    if (!input || typeof input !== 'string') return '';
    
    return input
      .replace(/[<>\"'&]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .substring(0, maxLength);
  }

  private leaveRoom(client: Socket, roomId: string) {
    const room = this.rooms.get(roomId);
    if (room && room.members.has(client.id)) {
      room.members.delete(client.id);
      room.memberPublicKeys.delete(client.id);
      client.leave(roomId);

      const user = this.users.get(client.id);
      if (user) {
        user.currentRoom = undefined;
      }

      this.logSecurity('USER_LEFT_ROOM', client.id, { roomId });

      if (room.members.size > 0) {
        client.to(roomId).emit('user-left', {
          message: `A user left the room`,
          memberCount: room.members.size,
          leftMemberId: client.id,
        });
      }

      if (room.members.size === 0) {
        setTimeout(() => {
          const currentRoom = this.rooms.get(roomId);
          if (currentRoom && currentRoom.members.size === 0) {
            this.rooms.delete(roomId);
            this.logSecurity('ROOM_CLEANED_UP', 'system', { roomId });
          }
        }, 300000);
      }
    }
  }

  private generateRoomId(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }

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
  }
}