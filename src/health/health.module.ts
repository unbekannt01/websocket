/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { HealthController } from './health.controller';
import { KeepAliveService } from './keep-alive.service';

@Module({
  imports: [ScheduleModule.forRoot()],
  controllers: [HealthController],
  providers: [KeepAliveService],
})
export class HealthModule {}
