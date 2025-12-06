import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type SessionDocument = Session & Document;

@Schema({ timestamps: true, expires: '7d' }) // auto delete after 7 days
export class Session {
    @Prop({ type: Types.ObjectId, ref: 'User', required: true })
    userId: Types.ObjectId;

    @Prop()
    userAgent: string;

    @Prop()
    ip: string;

    // you can still keep explicit expiry if you want
    @Prop({ type: Date })
    expiresAt: Date;
}

export const SessionSchema = SchemaFactory.createForClass(Session);