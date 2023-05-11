---
title: "The Making of Fuzzing Against the Machine: A Chill Tale"
excerpt: "History of how the idea of the book Fuzzing Against The Machine started and favorite chapters of the authors"
categories:
    - Fuzzing
    - Book
tags:
    - AFL
    - AFL++
    - QEMU
    - Fuzzing
sidebar:
    - title: "Available in Amazon!"
    - text: https://packt.link/Eduardo
    - image: "/assets/images/fuzzing_against_machine.jpg"
last_modified_at: 2023-05-11T06:55:00
toc: true
---

So, there we were, Christmas had just zoomed by, and life was kinda tough,
you know? We were all bummed about stuff that didn't quite make sense such as Covid.
That's when I hit up my buddy Eduardo on December 28th, 2021, a casual Tuesday, and
I was like, "Hey, dude, wanna help me write a book on something we can't
totally wrap our heads around?" Eduardo was in the middle of his first year
of Ph.D. and feeling kinda lost too, so he was like, "Why not?"

We got together at our fave hangout spot, the COSEC lab at UC3M in Leganés,
near Madrid, and just started doodling ideas on the whiteboard. We knew there
was some cool stuff from the past few years about vulnerability discovery,
automation, and emulation that we could put together. But man, writing a book
is no joke—it takes forever! Even though we decided to use examples from the
community, we still had to dive deep into them at the bit level to make sure
we were giving our readers something worth their time.

And so, our epic adventure began. We laughed, we cried, and we geeked out as
we decoded the digital universe and turned it into a chill read for everyone
who was as curious as we were.

<figure>
<a href="/assets/images/FuzzingATM/first_draft.jpeg"><img src="/assets/images/FuzzingATM/first_draft.jpeg"></a>
<figcaption>The first draft of the first episode of the book.</figcaption>
</figure>

## Most Important Chapters for Antonio

### Chapter 5: The Eluding One

During the summer of 2022, I had everything for the chapter on the VLC exploit
and patch ready to go. It was all saved on a microSD card from my Raspberry Pi.
But, like a total goof, I forgot to back it up, and when our reviewers came
back with notes, the card died, and I lost everything. I was so mad at myself,
but after redoing the whole thing, I realized the chapter needed even more work.
So, in a weird way, it was kinda a blessing in disguise.

### Chapter 7: The Support of Team FirmWire

I've been following Marius Muench and Grant Hernandez's work on baseband since
2020, and I've also been in touch with Aurelienne and Davide from team Avatar.
When we reached out to them for a review of our chapters, they were super
helpful and stoked about our project. We can't wait to gift some copies to
team FirmWire!

### Chapter 10: iOS

Trung Nguyen, the main dev behind this project, is a fantastic dude—always
down to help and offer advice. His work is seriously impressive, and we wanted
to give it some love by creating a rad PoC interface for fuzzing OS calls.
This chapter was tough, though—compiling Mach-O binaries on Linux was a
nightmare! We had to use a Mac for some stuff and find ways to help our readers
reproduce the exercises quickly.

Big thanks to everyone who helped, especially Eduardo. He taught me to approach
challenges with balance and thoughtfulness. I usually jump into things headfirst
and stress myself out, but this book was a great experience in learning how to
balance ambition, deadlines, and reality, all while juggling our day jobs.
Cheers, everyone!

## Most Important Chapters for Eduardo

### Chapter 2: History of Emulation

While it would be easier to choose as important chapters any of the technical ones, I have decided to start as important (and also a list of favorite chapters), with chapter number 2 "History of Emulation". This was one of those chapters that Antonio and I wrote during the first days of the book, we talked about all those times we spent playing around with famous emulators like *MAME* or these days with *RetroPie* (Operating System I have on my bartop Arcade Machine). We also reminded one bachelor thesis that talked about the process of writing an emulator. I think while not very technical, this chapter will make some people feel a little bit nostalgic about the past.

<figure>
<a href="/assets/images/FuzzingATM/bartop.jpg"><img src="/assets/images/FuzzingATM/bartop.jpg"></a>
<figcaption>Bartop Arcade Machine With a Raspberry and RetroPie.</figcaption>
</figure>

### Chapter 3: QEMU From the Ground

This chapter introduces the reader into the world of QEMU, we were those days working at COSEC and digging into the documentation from QEMU (as well as the Airbus Seclab blog), and understanding how the emulation process was done on this tool. It is great understanding how QEMU works, since it applies a process of binary translation, based on its own Intermediate Representation and different methods for those instructions that do not have a direct translation into other architectures. This chapter will make the reader realize how powerful QEMU is.

### Chapter 9: OpenWrt System Fuzzing for ARM

If I have to choose one chapter that I specially like and I remember writing is Chapter 9, a chapter that Antonio and I wrote while I was in Japan. Those days I was going to work to Qiqi's university, while she had one of classes I was trying to setup all the docker images for running TriforceAFL for ARM. Here the reader will see how powerful is using QEMU+AFL, fuzzing system calls from a system that is (probably) different to the reader's host machine.

I have to thank all those people who were there supporting me while doing this book. Of course, I have to thank Antonio for doing me join the crazy idea of writing a book about a topic I just had a small knowledge about, and allowed me to learn while writing. It was a long but nice journey. I hope you reader enjoy the book, as much as we did while writing it.

**See you space cowboy...**