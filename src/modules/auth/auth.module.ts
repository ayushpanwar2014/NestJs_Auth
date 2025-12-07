import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Session, SessionSchema } from 'src/database/schema/session.schema';
import { User, UserSchema } from 'src/database/schema/user.schema';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModule } from '../user/user.module';
import { AuthGuard } from 'src/common/guards/auth.guard';

@Module({
    imports: [
        MongooseModule.forFeature([
            { name: User.name, schema: UserSchema },
            { name: Session.name, schema: SessionSchema },
        ]),
        UserModule,
    ],
    controllers: [AuthController],
    providers: [AuthService, AuthGuard],
    exports: [AuthService],
})
export class AuthModule { }