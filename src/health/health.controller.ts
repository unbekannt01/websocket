/* eslint-disable prettier/prettier */
import { Controller, Get } from '@nestjs/common';

@Controller()
export class HealthController {
  private readonly startTime = Date.now();

  @Get('health')
  getHealth() {
    const uptimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);
    const hours = Math.floor(uptimeSeconds / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const seconds = uptimeSeconds % 60;

    return {
      success: true,
      message: 'Server is healthy',
      timestamp: new Date().toISOString(),
      uptime: `${hours}h ${minutes}m ${seconds}s`,
      environment: process.env.NODE_ENV || 'development',
    };
  }
}
