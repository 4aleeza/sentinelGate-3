"""Lab-only token generator. Never use real credentials or log output."""
import argparse
import os
import time
import jwt

def mint(variant, secret, now=None):
    now = int(time.time() if now is None else now)
    claims = {'sub':'lab-user', 'iat':now, 'exp':now+300, 'iss':'sentinelgate-lab',
              'aud':'sentinelgate-api', 'scope':'api:read api:write'}
    if variant == 'monitor': claims['scope'] = 'monitor:read'
    if variant == 'expired': claims['exp'] = now-60
    if variant == 'wrong-audience': claims['aud'] = 'wrong-audience'
    if variant == 'missing-claim': del claims['scope']
    if variant == 'insufficient-scope': claims['scope'] = 'api:write'
    if variant == 'none': return jwt.encode(claims, key='', algorithm='none')
    if variant == 'wrong-signature': secret = 'not-the-correct-signing-secret-32-bytes'
    return jwt.encode(claims, secret, algorithm='HS256')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('variant', choices=['valid','monitor','expired','wrong-signature','none','wrong-audience','missing-claim','insufficient-scope'])
    args = parser.parse_args()
    secret = os.environ.get('SENTINELGATE_JWT_SECRET', '')
    if len(secret.encode()) < 32: parser.error('SENTINELGATE_JWT_SECRET must contain at least 32 bytes')
    print(mint(args.variant, secret))
