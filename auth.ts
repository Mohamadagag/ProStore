import NextAuth from 'next-auth'
import {PrismaAdapter} from '@auth/prisma-adapter'
import {prisma} from '@/db/prisma'
import CredentialsProvider from "next-auth/providers/credentials"
import { compareSync } from 'bcrypt-ts-edge'
import { cookies } from 'next/headers'

// import type { NextAuthConfig } from 'next-auth'
// import { NextResponse } from 'next/server'
import { authConfig } from './auth.config'
import { NextResponse } from 'next/server'

export const config = {
    pages:{
        signIn: '/sign-in',
        error: '/sign-in',
    },
    session:{
        strategy: 'jwt' as const,
        maxAge: 30 * 24 * 60 *60, // 30 days
    },
    adapter: PrismaAdapter(prisma),
    providers: [
        CredentialsProvider({
            credentials: {
                email: { type: "email" },
                password: { type: "password" }
              },
              async authorize(credentials){
                if(credentials == null) return null;

                // Find user in database
                const user = await prisma.user.findFirst({
                    where:{
                        email: credentials.email as string
                    }
                })

                // check if user exists and if passwor matches
                if(user && user.password){
                    const isMatch = compareSync(credentials.password as string, user.password)
                    // if password matches return user
                    if(isMatch) {
                        return {
                            id: user.id,
                            name: user.name,
                            email: user.email,
                            role: user.role
                        }
                    }
                }

                // if user does not exist or pass does not match return null
                return null
              }
        })
    ],
    callbacks: {
        async session({ session, user,trigger, token }: any) {
            // set user id from the token
            session.user.id = token.sub
            session.user.role = token.role
            session.user.name = token.name

            // if there is an update set the user name
            if(trigger === 'update'){
                session.user.name = user.name
            }
            return session
          },

          async jwt({token, user, trigger, session}:any){
            if(user){
                token.id = user.id
                token.role = user.role

                if(user.name === 'NO_NAME') {
                    token.name = user.email.split('@')[0]

                    await prisma.user.update({
                        where: {id:user.id},
                        data: {name: token.name}
                    })
                }

                if(trigger === 'signIn' || trigger === 'signUp'){
                    const cookiesObject = await cookies()
                    const sessionCartId = cookiesObject.get('sessionCartId')?.value

                    if(sessionCartId) {
                        const sessionCart = await prisma.cart.findFirst({
                            where: {sessionCartId}
                        })

                        if(sessionCart){
                            await prisma.cart.deleteMany({
                                where : {userId: user.id}
                            })

                            await prisma.cart.update({
                                where: { id: sessionCart.id },
                                data: { userId: user.id },
                              });
                        }
                    }
                }
            }

            // handle session update
            if(session?.user.name && trigger === 'update'){
                token.name = session.user.name;
            }

            return token
          },
          ...authConfig.callbacks,
          authorized({request, auth}: any){
            const protectedPaths = [
                /\/shipping-address/,
                /\/payment-method/,
                /\/place-order/,
                /\/profile/,
                /\/admin/,
                /\/user\/(.*)/,
                /\/order\/(.*)/,
            ]

            const {pathname} =request.nextUrl

            if(!auth && protectedPaths.some((p) => p.test(pathname) )) return false 

            if(!request.cookies.get('sessionCartId')){
                const sessionCartId = crypto.randomUUID();
                const newRequestHeaders = new Headers(request.headers)
                const response = NextResponse.next({
                    request: {
                        headers: newRequestHeaders
                    }
                })
                response.cookies.set('sessionCartId', sessionCartId)
                return response
            }else{
                return true
            }
          }
    }
}

export const {handlers, auth, signIn, signOut} = NextAuth(config)