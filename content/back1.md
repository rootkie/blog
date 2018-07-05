---
title: "Lorem ipsum dolor sit amet, consectetur adipisicing elit. Quod totam, laborum? Neque perspiciatis harum, rem non ea! Repudiandae nulla, omnis? Et, est. Dicta repellat commodi, molestiae voluptatibus cumque aspernatur similique!"
date: 2018-05-03T18:31:54+08:00
draft: true
categories: ["testing","oh"]
tags: ["random","1st"]
---

**This is a test posts**

- test 1
- test 2
- test 3

Lorem ipsum dolor sit amet, consectetur adipisicing elit. Obcaecati dolores quam unde vitae error rerum beatae. Veniam quibusdam, architecto sequi eius non sapiente ipsum eveniet obcaecati eum cupiditate! Saepe, soluta.

```javascript
deleteStudent = (studentIds) => {
  const studentRequestPromises = []
  for (let studentId of studentIds) {
    studentRequestPromises.push(
      axios.delete('/students',
        {
          headers: {
            'Content-Type': 'application/json',
            'x-access-token': localStorage.token
          },
          data: {
            studentId
          }
        })
    )
  }
}
```

```python
import random

def main(){
    # this creates some random number
    for i in range(10):
        print random.randint()

}
```