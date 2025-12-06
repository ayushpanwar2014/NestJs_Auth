import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import configuration from './config/configuration';
import { AuthModule } from './modules/auth/auth.module';
import { SecurityMiddleware } from './common/middleware/security.middleware';
import { AuthMiddleware } from './common/middleware/auth.middleware';
import { UserController } from './modules/user/user.controller';
import { UserModule } from './modules/user/user.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),
    MongooseModule.forRoot(process.env.MONGO_URI!),
    AuthModule,
    UserModule,
  ],
  controllers: [UserController],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Security middleware applied to all routes
    consumer.apply(SecurityMiddleware).forRoutes('*');

    // Auth middleware for protected routes (example)
    consumer
      .apply(AuthMiddleware)
      .forRoutes('users/me'); // you can expand this later
  }
}