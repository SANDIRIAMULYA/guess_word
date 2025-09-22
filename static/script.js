document.addEventListener("DOMContentLoaded",()=>{
  let g=document.querySelector('input[name="guess"]');
  if(g){g.addEventListener("input",()=>g.value=g.value.toUpperCase());}
});
