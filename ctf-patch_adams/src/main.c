#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

void unauthorized();
char* get_quote();
void heal();
bool is_adams_pc();

void unauthorized() {
    printf("Unauthorized\n");
}

char* get_quote() {
    char* quotes[] = {
        "You treat a disease, you win, you lose. You treat a person, I guarantee you, you'll win, no matter what the outcome.",
        "I love you without knowing how, or when, or from where. I love you straightforwardly without complexities or pride. I love you because I know no other way then this. So close that your hand, on my chest, is my hand. So close, that when you close your eyes, I fall asleep.",
        "Our job is improving the quality of life, not just delaying death.",
        "You're focusing on the problem. If you focus on the problem, you can't see the solution. Never focus on the problem!",
        "What's wrong with death sir? What are we so mortally afraid of? Why can't we treat death with a certain amount of humanity and dignity, and decency, and God forbid, maybe even humor. Death is not the enemy gentlemen. If we're going to fight a disease, let's fight one of the most terrible diseases of all, indifference.",
        "See what no one else sees. See what everyone chooses not to see... out of fear, conformity or laziness. See the whole world anew each day!",
        "We can head on down to the maternity ward. You know those chicks put out.",
        "We need to start treating the patient as well as the disease",
        "I wanted to become a doctor so I could serve others. And because of that, I've lost everything. But I've also gained everything."
    };

    return quotes[rand() % (sizeof(quotes) / sizeof(quotes[0]))];
}

bool is_adams_pc() {
    FILE *file = fopen("/etc/hostname", "r");

    if (file != NULL) {
        char hostname[20];
        fscanf(file, "%s", hostname);

        fclose(file);

        if (strcmp(hostname, "adams-pc") == 0) {
            return true;
        }
    } else {
        printf("Error: /etc/hostname not found\n");
    }

    return false;
}

void heal() {
    FILE *file = fopen("/secret/flag.txt", "r");

    if (file != NULL) {
        char flag[100];
        fgets(flag, sizeof(flag), file);

        printf("%s\n", flag);

        fclose(file);
    } else {
        printf("Error: flag.txt not found\n");
    }
}

int main() {
    srand(time(NULL));

    if (is_adams_pc()) {
        printf("%s\n", get_quote());
    } else {
        unauthorized();
    }

    return 0;
}
