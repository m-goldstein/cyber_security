#!/usr/bin/env python3
# -*- coding: latin-1 -*-
msgs = ['I come in peace.','Prepare to be destroyed!']
blob = """
               �gb(����KCtD���`�k$,"C�.>Fy����<,<�g��!��J�z��b�M*�hpq�g�g\A�v�;.вT�=�ؓt�"�-�@G&`�����Â>4A
T���ѯa�42��0�Ǹ�"""
from hashlib import sha256
if sha256(blob.encode()).hexdigest() == '139b0006e10b65f1a453605de820f785893d78785a726af56a390170ba08ec43':
    print(msgs[0])
else:
    print(msgs[1])
