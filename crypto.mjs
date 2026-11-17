const encoder=new TextEncoder();
export const fromBase64=value=>Uint8Array.from(atob(value),c=>c.charCodeAt(0));
export function toBase64(bytes){let text='';for(const value of bytes)text+=String.fromCharCode(value);return btoa(text);}
export function validatePacket(packet){
  if(packet?.version!==1||packet.algorithm!=='AES-GCM'||packet.kdf!=='PBKDF2-SHA256'||packet.iterations!==600000)throw new Error('Formato non supportato');
  if(fromBase64(packet.salt).length!==16||fromBase64(packet.iv).length!==12)throw new Error('Formato non valido');
}
export async function derivePasswordKey(password,packet){
  validatePacket(packet);
  const material=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:fromBase64(packet.salt),iterations:packet.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},true,['decrypt']);
}
export async function decryptWithKey(packet,key){
  validatePacket(packet);
  const bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromBase64(packet.iv),tagLength:128},key,fromBase64(packet.ciphertext));
  return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
}
export async function decryptPacket(packet,password){return decryptWithKey(packet,await derivePasswordKey(password,packet));}
