import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity('users')
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    first_name: string;

    @Column()
    last_name: string;

    @Column({ unique: true }) // unique: 唯一
    email: string;

    @Column()
    password: string;

    @Column({ default: true })
    is_ambassador: boolean;
}
